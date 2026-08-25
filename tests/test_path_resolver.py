# tests/test_path_resolver.py
import os
import pytest
from parsers import path_resolver

def test_catalog_retrieval():
    catalog = path_resolver.get_catalog()
    assert len(catalog) >= 10
    ids = [item["id"] for item in catalog]
    assert "prefetch" in ids
    assert "browser_history" in ids
    assert "powershell_history" in ids
    assert "userassist" in ids
    assert "usb_devices" in ids
    assert "bam_dam" in ids
    assert "event_logs" in ids

def test_presets_retrieval():
    presets = path_resolver.get_presets()
    assert len(presets) >= 6
    preset_ids = [p["id"] for p in presets]
    assert "all_triage" in preset_ids
    assert "execution_persistence" in preset_ids
    assert "browser_downloads" in preset_ids

def test_target_scan_classification(tmp_path):
    # Create mock files
    (tmp_path / "calc.exe-12345678.pf").write_bytes(b"SCCA\x00\x00")
    (tmp_path / "test.lnk").write_bytes(b"\x4c\x00\x00\x00")
    (tmp_path / "ConsoleHost_history.txt").write_text("whoami\n", encoding="utf-8")
    
    results = path_resolver.scan_target_directory(str(tmp_path))
    assert "prefetch" in results
    assert len(results["prefetch"]) == 1
    assert "lnk" in results
    assert "powershell_history" in results
