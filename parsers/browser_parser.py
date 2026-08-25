# parsers/browser_parser.py
"""
Browser Forensics Parser.
Extracts:
- Visited URLs, page titles, visit counts, typed counts, last visit times
- File downloads: target path, URL source, file size, download time
Supports:
- Chromium-based: Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi (History SQLite)
- Mozilla Firefox: places.sqlite (moz_places, moz_annos, moz_historyvisits)
"""

import os
import sqlite3
import shutil
import tempfile
import datetime
import json
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

def _webkit_time_to_iso(webkit_ts: Optional[int]) -> Optional[str]:
    """
    Converts WebKit timestamp (microseconds since Jan 1, 1601 UTC) to ISO-8601 string.
    """
    if not webkit_ts or webkit_ts <= 0:
        return None
    try:
        epoch_delta = 11644473600  # seconds between 1601-01-01 and 1970-01-01
        seconds = (webkit_ts / 1_000_000.0) - epoch_delta
        dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        return normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        return None

def _prtime_to_iso(prtime_us: Optional[int]) -> Optional[str]:
    """
    Converts Mozilla PRTime (microseconds since Jan 1, 1970 UTC) to ISO-8601 string.
    """
    if not prtime_us or prtime_us <= 0:
        return None
    try:
        dt = datetime.datetime.fromtimestamp(prtime_us / 1_000_000.0, tz=datetime.timezone.utc)
        return normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        return None

def _copy_locked_db(db_path: str) -> Optional[str]:
    """
    Safely copies a potentially locked SQLite database file to a temporary file.
    """
    try:
        temp_dir = tempfile.mkdtemp(prefix="wab_browser_")
        temp_file = os.path.join(temp_dir, os.path.basename(db_path))
        shutil.copy2(db_path, temp_file)
        # Also copy WAL and SHM files if present
        for ext in ["-wal", "-shm", ".wal", ".shm"]:
            wal_source = db_path + ext
            if os.path.exists(wal_source):
                try:
                    shutil.copy2(wal_source, temp_file + ext)
                except Exception:
                    pass
        return temp_file
    except Exception:
        return None

def _cleanup_temp_copy(temp_file_path: Optional[str]):
    if not temp_file_path:
        return
    try:
        temp_dir = os.path.dirname(temp_file_path)
        if os.path.isdir(temp_dir) and "wab_browser_" in temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass

def parse_chromium_history(db_path: str) -> List[Dict[str, Any]]:
    """
    Parses a Chromium 'History' SQLite database (Chrome, Edge, Brave, Opera).
    """
    records = []
    temp_path = _copy_locked_db(db_path)
    target_path = temp_path if temp_path else db_path

    try:
        conn = sqlite3.connect(f"file:{target_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # 1. Parse Visited URLs
        try:
            cur.execute("""
                SELECT id, url, title, visit_count, typed_count, last_visit_time
                FROM urls
                WHERE last_visit_time > 0
                ORDER BY last_visit_time DESC
                LIMIT 5000
            """)
            for row in cur.fetchall():
                ts = _webkit_time_to_iso(row["last_visit_time"])
                url = row["url"] or ""
                title = row["title"] or ""
                visit_count = row["visit_count"] or 1
                typed_count = row["typed_count"] or 0

                extra_dict = {
                    "source": "chromium_history",
                    "title": title[:200] if title else "",
                    "visit_count": visit_count,
                    "typed_count": typed_count,
                    "url": url[:400]
                }
                extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                records.append({
                    "artifact_type": "browser_url",
                    "name": title[:80] if title else url[:80],
                    "path": url,
                    "timestamp": ts,
                    "last_access": None,
                    "extra": extra_str,
                    "details": json.dumps({"url": url, "title": title, "visit_count": visit_count, "typed_count": typed_count})
                })
        except Exception as e:
            pass

        # 2. Parse Downloads
        try:
            cur.execute("""
                SELECT id, current_path, target_path, start_time, end_time, total_bytes, tab_url
                FROM downloads
                ORDER BY start_time DESC
            """)
            for row in cur.fetchall():
                ts = _webkit_time_to_iso(row["start_time"])
                download_path = row["target_path"] or row["current_path"] or "Unknown"
                filename = os.path.basename(download_path)
                tab_url = row["tab_url"] if "tab_url" in row.keys() else ""
                bytes_size = row["total_bytes"] or 0

                extra_dict = {
                    "source": "chromium_download",
                    "target_path": download_path,
                    "size_bytes": bytes_size,
                    "source_url": tab_url[:300] if tab_url else ""
                }
                extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                records.append({
                    "artifact_type": "browser_download",
                    "name": filename,
                    "path": download_path,
                    "timestamp": ts,
                    "last_access": None,
                    "extra": extra_str,
                    "details": json.dumps({"download_path": download_path, "bytes": bytes_size, "url": tab_url})
                })
        except Exception:
            pass

        conn.close()
    except Exception as e:
        pass
    finally:
        _cleanup_temp_copy(temp_path)

    return records

def parse_firefox_places(db_path: str) -> List[Dict[str, Any]]:
    """
    Parses a Mozilla Firefox 'places.sqlite' database.
    """
    records = []
    temp_path = _copy_locked_db(db_path)
    target_path = temp_path if temp_path else db_path

    try:
        conn = sqlite3.connect(f"file:{target_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        try:
            cur.execute("""
                SELECT p.id, p.url, p.title, p.visit_count, p.typed, p.last_visit_date
                FROM moz_places p
                WHERE p.last_visit_date > 0
                ORDER BY p.last_visit_date DESC
                LIMIT 5000
            """)
            for row in cur.fetchall():
                ts = _prtime_to_iso(row["last_visit_date"])
                url = row["url"] or ""
                title = row["title"] or ""
                visit_count = row["visit_count"] or 1
                typed = row["typed"] or 0

                extra_dict = {
                    "source": "firefox_places",
                    "title": title[:200] if title else "",
                    "visit_count": visit_count,
                    "typed": typed,
                    "url": url[:400]
                }
                extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                records.append({
                    "artifact_type": "browser_url",
                    "name": title[:80] if title else url[:80],
                    "path": url,
                    "timestamp": ts,
                    "last_access": None,
                    "extra": extra_str,
                    "details": json.dumps({"url": url, "title": title, "visit_count": visit_count})
                })
        except Exception:
            pass

        conn.close()
    except Exception:
        pass
    finally:
        _cleanup_temp_copy(temp_path)

    return records

def parse_browser_artifact(path: str) -> List[Dict[str, Any]]:
    """
    General entry point for any browser history file or directory.
    """
    records = []
    if not os.path.exists(path):
        return records

    if os.path.isfile(path):
        base_name = os.path.basename(path).lower()
        if "places.sqlite" in base_name:
            records.extend(parse_firefox_places(path))
        elif "history" in base_name or base_name.endswith(".sqlite") or base_name.endswith(".db"):
            # Try Chromium parser first
            res = parse_chromium_history(path)
            if not res:
                res = parse_firefox_places(path)
            records.extend(res)
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files:
                f_lower = f.lower()
                full_f = os.path.join(root, f)
                if f_lower == "history":
                    records.extend(parse_chromium_history(full_f))
                elif f_lower == "places.sqlite":
                    records.extend(parse_firefox_places(full_f))

    return records

def parse_all_live_browsers() -> List[Dict[str, Any]]:
    """
    Scans standard paths for all installed web browsers on the live system.
    """
    records = []
    user_prof = os.environ.get("USERPROFILE", "")
    local_app = os.environ.get("LOCALAPPDATA", "")
    app_data = os.environ.get("APPDATA", "")

    candidate_paths = [
        # Chrome
        os.path.join(local_app, r"Google\Chrome\User Data\Default\History"),
        # Edge
        os.path.join(local_app, r"Microsoft\Edge\User Data\Default\History"),
        # Brave
        os.path.join(local_app, r"BraveSoftware\Brave-Browser\User Data\Default\History"),
        # Opera
        os.path.join(app_data, r"Opera Software\Opera Stable\History"),
        # Vivaldi
        os.path.join(local_app, r"Vivaldi\User Data\Default\History"),
    ]

    # Firefox profiles
    ff_profiles_dir = os.path.join(app_data, r"Mozilla\Firefox\Profiles")
    if os.path.isdir(ff_profiles_dir):
        try:
            for p_dir in os.listdir(ff_profiles_dir):
                places_path = os.path.join(ff_profiles_dir, p_dir, "places.sqlite")
                if os.path.isfile(places_path):
                    candidate_paths.append(places_path)
        except Exception:
            pass

    for path in candidate_paths:
        if os.path.isfile(path):
            records.extend(parse_browser_artifact(path))

    return records
