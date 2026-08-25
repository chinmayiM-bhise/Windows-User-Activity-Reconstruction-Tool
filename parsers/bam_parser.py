# parsers/bam_parser.py
r"""
Background Activity Moderator (BAM) and Desktop Activity Moderator (DAM) Parser.
BAM is a Windows kernel service introduced in Windows 10 (1709) that records
full paths and last execution timestamps of executables executed per User SID.
"""

import os
import struct
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

def _filetime_to_iso(filetime: int) -> Optional[str]:
    if not filetime or filetime <= 0:
        return None
    try:
        us = filetime / 10.0
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        dt = epoch + datetime.timedelta(microseconds=us)
        return normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        return None

def parse_live_bam() -> List[Dict[str, Any]]:
    r"""
    Parses BAM & DAM settings under HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
    and dam\UserSettings.
    """
    records = []
    if not HAS_WINREG:
        return records

    base_services = [
        (r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", "BAM"),
        (r"SYSTEM\CurrentControlSet\Services\bam\UserSettings", "BAM"),
        (r"SYSTEM\CurrentControlSet\Services\dam\UserSettings", "DAM"),
    ]

    for service_path, service_type in base_services:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, service_path) as root_key:
                sid_count, _, _ = winreg.QueryInfoKey(root_key)
                for i in range(sid_count):
                    try:
                        sid = winreg.EnumKey(root_key, i)
                        sid_path = f"{service_path}\\{sid}"

                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_path) as user_key:
                            val_count, _, _ = winreg.QueryInfoKey(user_key)
                            for j in range(val_count):
                                try:
                                    val_name, val_data, val_type = winreg.EnumValue(user_key, j)
                                    # Ignore system values like SequenceNumber or Version
                                    if val_name.lower() in ("sequencenumber", "version"):
                                        continue

                                    if not isinstance(val_data, (bytes, bytearray)) or len(val_data) < 8:
                                        continue

                                    # First 8 bytes is FILETIME
                                    filetime = struct.unpack_from("<Q", val_data, 0)[0]
                                    ts = _filetime_to_iso(filetime)

                                    exe_name = os.path.basename(val_name.replace("/", "\\")) or val_name

                                    extra_dict = {
                                        "source": f"registry:{service_type.lower()}",
                                        "user_sid": sid,
                                        "service": service_type,
                                        "full_path": val_name
                                    }
                                    extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                                    records.append({
                                        "artifact_type": "bam_execution",
                                        "name": exe_name[:80],
                                        "path": val_name,
                                        "timestamp": ts,
                                        "last_access": None,
                                        "extra": extra_str,
                                        "details": str({
                                            "executable": val_name,
                                            "user_sid": sid,
                                            "service": service_type,
                                            "timestamp": ts
                                        })
                                    })
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except (FileNotFoundError, OSError):
            continue
        except Exception:
            continue

    return records
