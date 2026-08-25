# parsers/userassist_parser.py
r"""
Windows UserAssist Forensics Parser.
Decodes:
- ROT13 encoded GUI application execution names
- Execution count, Focus count, Focus duration
- Last execution timestamp (FILETIME)
Sources:
- Live Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
- Offline parsed records
"""

import os
import codecs
import struct
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# Known UserAssist GUIDs
USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable Applications",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcuts / LNKs",
    "{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Internet Explorer / Explorer Apps",
    "{75048700-EF1F-11D0-9888-006097DEACF9}": "Active Desktop Items",
    "{BCB48336-4DA5-4E25-AC8E-E61576E3952C}": "Control Panel Applets",
}

def _rot13(s: str) -> str:
    """Decodes ROT-13 obfuscated string."""
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s

def _filetime_to_iso(filetime: int) -> Optional[str]:
    """Converts 64-bit Windows FILETIME to ISO UTC string."""
    if not filetime or filetime <= 0:
        return None
    try:
        us = filetime / 10.0
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch + datetime.timedelta(microseconds=us)
        return normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        return None

def _parse_userassist_value_data(raw_data: bytes) -> Dict[str, Any]:
    """
    Parses UserAssist binary blob (Windows 7/8/10/11 72-byte structure).
    """
    info = {
        "run_count": None,
        "focus_count": None,
        "focus_time_ms": None,
        "last_execution_time": None
    }
    if not raw_data or len(raw_data) < 16:
        return info

    try:
        if len(raw_data) >= 72:
            # Modern Windows structure (Win 7 - Win 11)
            # Offset 4: Run count (DWORD)
            # Offset 8: Focus count (DWORD)
            # Offset 12: Focus time in ms (DWORD)
            # Offset 60: Last execution FILETIME (QWORD)
            run_count = struct.unpack_from("<I", raw_data, 4)[0]
            focus_count = struct.unpack_from("<I", raw_data, 8)[0]
            focus_time_ms = struct.unpack_from("<I", raw_data, 12)[0]
            filetime = struct.unpack_from("<Q", raw_data, 60)[0]

            info["run_count"] = run_count
            info["focus_count"] = focus_count
            info["focus_time_ms"] = focus_time_ms
            info["last_execution_time"] = _filetime_to_iso(filetime)
        elif len(raw_data) >= 16:
            # Legacy structure
            run_count = struct.unpack_from("<I", raw_data, 4)[0]
            # Session count or offset adjustments
            if run_count > 5:
                run_count -= 5  # Legacy offset adjustment
            filetime = struct.unpack_from("<Q", raw_data, 8)[0] if len(raw_data) >= 16 else 0
            info["run_count"] = max(0, run_count)
            info["last_execution_time"] = _filetime_to_iso(filetime)
    except Exception:
        pass

    return info

def parse_live_userassist() -> List[Dict[str, Any]]:
    """
    Extracts and parses UserAssist entries from the live Windows Registry.
    """
    records = []
    if not HAS_WINREG:
        return records

    base_key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key_path) as ua_key:
            guid_count, _, _ = winreg.QueryInfoKey(ua_key)
            for i in range(guid_count):
                try:
                    guid_name = winreg.EnumKey(ua_key, i)
                    guid_desc = USERASSIST_GUIDS.get(guid_name.upper(), "UserAssist Subkey")
                    count_sub_path = f"{base_key_path}\\{guid_name}\\Count"

                    try:
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_sub_path) as count_key:
                            _, val_count, _ = winreg.QueryInfoKey(count_key)
                            for v_idx in range(val_count):
                                try:
                                    val_name, val_data, _ = winreg.EnumValue(count_key, v_idx)
                                    decoded_name = _rot13(val_name)
                                    if not isinstance(val_data, (bytes, bytearray)):
                                        continue

                                    parsed_data = _parse_userassist_value_data(val_data)
                                    ts = parsed_data.get("last_execution_time")
                                    run_count = parsed_data.get("run_count")
                                    focus_count = parsed_data.get("focus_count")
                                    focus_time_ms = parsed_data.get("focus_time_ms")

                                    # Clean up display name
                                    display_name = os.path.basename(decoded_name) or decoded_name

                                    extra_dict = {
                                        "source": "registry:userassist",
                                        "guid": guid_name,
                                        "category": guid_desc,
                                        "run_count": run_count,
                                        "focus_count": focus_count,
                                        "focus_time_seconds": round(focus_time_ms / 1000.0, 2) if focus_time_ms else 0,
                                        "full_name": decoded_name[:300]
                                    }
                                    extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                                    records.append({
                                        "artifact_type": "userassist",
                                        "name": display_name[:100],
                                        "path": decoded_name,
                                        "timestamp": ts,
                                        "last_access": None,
                                        "extra": extra_str,
                                        "details": str({
                                            "program": decoded_name,
                                            "run_count": run_count,
                                            "focus_count": focus_count,
                                            "focus_time_ms": focus_time_ms,
                                            "guid": guid_name
                                        })
                                    })
                                except Exception:
                                    continue
                    except (FileNotFoundError, OSError):
                        continue
                except Exception:
                    continue
    except Exception:
        pass

    return records
