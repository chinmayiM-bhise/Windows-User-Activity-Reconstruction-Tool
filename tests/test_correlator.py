# tests/test_correlator.py
import sqlite3
import pytest
from correlator import correlate_artifacts
import core_logic

def test_correlator_sessionization_and_anomaly(tmp_path):
    db_path = str(tmp_path / "test_artifacts.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE artifacts (
            id INTEGER PRIMARY KEY,
            artifact_type TEXT,
            name TEXT,
            path TEXT,
            timestamp TEXT,
            last_access TEXT,
            extra TEXT,
            details TEXT
        )
    """)
    # 1. Download event
    cur.execute("""
        INSERT INTO artifacts (artifact_type, name, path, timestamp, extra)
        VALUES ('browser_download', 'payload.exe', 'C:\\Users\\User\\Downloads\\payload.exe', '2026-08-25T10:00:00Z', 'source=browser')
    """)
    # 2. Immediate execution in Temp directory (5 seconds later)
    cur.execute("""
        INSERT INTO artifacts (artifact_type, name, path, timestamp, extra)
        VALUES ('prefetch', 'PAYLOAD.EXE-12345678.pf', 'C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe', '2026-08-25T10:00:05Z', 'run_count=1')
    """)
    conn.commit()
    conn.close()

    results = correlate_artifacts(db_path)
    assert len(results) == 2
    assert results[0]["session"] == 1
    assert results[1]["session"] == 1
    # Check pipeline anomaly detection
    assert "Immediate Execution After Web Download" in results[1]["anomaly"] or "Temp Directory" in results[1]["anomaly"]
