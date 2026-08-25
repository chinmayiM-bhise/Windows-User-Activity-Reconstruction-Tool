# parsers/jumplist_parser.py
r"""
Windows Jump Lists Parser (AutomaticDestinations & CustomDestinations).
Extracts:
- Recently opened documents, pinned items, and frequently accessed files
- AppID resolution (identifies which software opened the file)
- Timestamps and target paths
"""

import os
import re
import struct
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

# Known Application AppIDs mapped to software names
KNOWN_APPIDS = {
    "9b9cdc69c1c24e2b": "Notepad",
    "12d3583525287f34": "WordPad",
    "adecfb853d77462a": "Microsoft Word 2016/2019/365",
    "a7bd71699cd38d1c": "Microsoft Excel 2016/2019/365",
    "7e4dca80246863e3": "Microsoft PowerPoint",
    "5d696d521de238c3": "Windows Media Player",
    "cdf30b95c55fd78d": "Windows Media Player 12",
    "f015630372ed436b": "Windows File Explorer",
    "28c8b4a0c24b1a2b": "Internet Explorer",
    "1b7e638830985049": "Google Chrome",
    "d00655d2aa124e6f": "Microsoft Edge",
    "3b6038393582496d": "Paint",
    "918e0ecb43d17e23": "Command Prompt",
    "1178bc166d3a958a": "Windows PowerShell",
}

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

def _extract_strings_utf16_ascii(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts human-readable file paths and strings from raw binary stream."""
    strings = []
    # Try finding file paths with regex (e.g. C:\... or \\...)
    # ASCII paths
    ascii_matches = re.findall(rb"([a-zA-Z]:\\[a-zA-Z0-9_\-\.\ \\\/]+)", data)
    for m in ascii_matches:
        try:
            s = m.decode("ascii", errors="ignore").strip()
            if len(s) >= min_len and ("." in s or "\\" in s):
                strings.append(s)
        except Exception:
            pass

    # UTF-16LE paths
    utf16_matches = re.findall(rb"((?:[a-zA-Z]\x00:\x00\\\x00)(?:[^\x00]\x00){3,})", data)
    for m in utf16_matches:
        try:
            s = m.decode("utf-16le", errors="ignore").strip()
            if len(s) >= min_len:
                strings.append(s)
        except Exception:
            pass

    return list(dict.fromkeys(strings))

def parse_jumplist_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parses an individual .automaticDestinations-ms or .customDestinations-ms file.
    """
    records = []
    if not os.path.isfile(file_path):
        return records

    try:
        filename = os.path.basename(file_path).lower()
        appid_hex = filename.split(".")[0]
        app_name = KNOWN_APPIDS.get(appid_hex, f"AppID ({appid_hex})")

        mtime = os.path.getmtime(file_path)
        dt = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc)
        file_ts = normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))

        with open(file_path, "rb") as f:
            data = f.read()

        extracted_paths = _extract_strings_utf16_ascii(data)

        if extracted_paths:
            for p in extracted_paths[:25]:  # limit to top 25 per jumplist
                entry_name = os.path.basename(p) or p
                extra_dict = {
                    "source": "jumplist",
                    "appid": appid_hex,
                    "application": app_name,
                    "target_path": p
                }
                extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                records.append({
                    "artifact_type": "jumplist_entry",
                    "name": f"[{app_name}] {entry_name[:50]}",
                    "path": p,
                    "timestamp": file_ts,
                    "last_access": file_ts,
                    "extra": extra_str,
                    "details": str({"appid": appid_hex, "application": app_name, "path": p, "jumplist_file": filename})
                })
        else:
            # Record general jumplist modification
            records.append({
                "artifact_type": "jumplist",
                "name": f"JumpList: {app_name}",
                "path": file_path,
                "timestamp": file_ts,
                "last_access": file_ts,
                "extra": f"source=jumplist;appid={appid_hex};application={app_name}",
                "details": str({"appid": appid_hex, "application": app_name, "jumplist_file": filename})
            })

    except Exception:
        pass

    return records

def parse_live_jumplists() -> List[Dict[str, Any]]:
    r"""
    Parses all Jump Lists under %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations
    and CustomDestinations.
    """
    records = []
    app_data = os.environ.get("APPDATA", "")
    target_dirs = [
        os.path.join(app_data, r"Microsoft\Windows\Recent\AutomaticDestinations"),
        os.path.join(app_data, r"Microsoft\Windows\Recent\CustomDestinations"),
    ]

    for d in target_dirs:
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    full_p = os.path.join(d, f)
                    if os.path.isfile(full_p):
                        records.extend(parse_jumplist_file(full_p))
            except Exception:
                pass

    return records
