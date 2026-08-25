# core_logic.py
"""
Core Logic Orchestration for Windows Forensic Artifacts Parser.
Orchestrates:
- Live System Auto-Triage & Offline Image / Directory Scanner
- Database persistence (SQLite)
- Categorized artifact parsing (Prefetch, LNK, Recycle Bin, ShellBags, Browsers, PowerShell, UserAssist, USB, BAM, Startup, EVTX, JumpLists)
- Statistical summaries, PDF reporting, CSV/JSON timeline exports
"""

import os
import sqlite3
import datetime
import hashlib
import json
import tempfile
import getpass
import platform
import socket
import logging
import csv
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import DB utilities and schema
try:
    from db.db_utils import open_db, execute_with_retry
    from db.schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk, clear_database
except ImportError:
    try:
        from db_utils import open_db, execute_with_retry
        from schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk, clear_database
    except ImportError:
        open_db = None
        execute_with_retry = None
        init_db = None
        insert_artifact = None
        query_artifacts = None
        insert_artifacts_bulk = None
        clear_database = None

# Import all forensic parsers
try:
    from parsers import (
        report_gen,
        prefetch_parser,
        lnk_parser,
        recycle_parser,
        shellbags_parser,
        browser_parser,
        powershell_parser,
        userassist_parser,
        usb_parser,
        bam_parser,
        startup_parser,
        evtx_parser,
        jumplist_parser,
        path_resolver,
    )
except ImportError:
    import report_gen
    import prefetch_parser
    import lnk_parser
    import recycle_parser
    import shellbags_parser
    import browser_parser
    import powershell_parser
    import userassist_parser
    import usb_parser
    import bam_parser
    import startup_parser
    import evtx_parser
    import jumplist_parser
    import path_resolver

# Import correlator
try:
    from correlator import correlate_artifacts
except ImportError:
    correlate_artifacts = None

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DB_PATH = "artifacts.db"
TOOL_VERSION = "v1.3.0"

def _sha256_file(path: str) -> str:
    """Calculates the SHA256 hash of a file."""
    try:
        if not os.path.exists(path):
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating SHA256 for {path}: {e}")
        return ""

def build_metadata(db_path: str) -> dict:
    """Builds metadata for forensic reports."""
    meta = {}
    try:
        meta["Examiner"] = getpass.getuser()
    except Exception:
        meta["Examiner"] = "Forensic Examiner"
    try:
        meta["Source"] = socket.gethostname()
    except Exception:
        meta["Source"] = "Windows Host"
    meta["OS"] = f"{platform.system()} {platform.release()} ({platform.version()})"
    meta["Tool Version"] = TOOL_VERSION
    meta["Generated"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    meta["DB SHA256"] = _sha256_file(db_path)
    meta["Case ID"] = ""
    meta["Evidence ID"] = ""
    meta["Description"] = ""
    meta["Notes"] = ""
    return meta

def _make_counts_chart(rows: List[Dict[str, Any]], outpath: str):
    """Generates a bar chart of artifact counts by type."""
    types = [r.get("artifact_type") or "unknown" for r in rows]
    counts = {}
    for t in types:
        counts[t] = counts.get(t, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]  # top 10
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    if not labels:
        labels = ["No Data"]
        values = [0]

    fig, ax = plt.subplots(figsize=(7.0, 3.0), dpi=150)
    colors_list = ["#2E7D32", "#1565C0", "#EF6C00", "#C62828", "#6A1B9A", "#00838F", "#4E342E", "#37474F", "#D84315", "#4527A0"]
    bars = ax.bar(range(len(labels)), values, color=colors_list[:len(labels)])
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=35, ha="right", fontsize=8)
    ax.set_ylabel("Record Count")
    ax.set_title("Artifact Distribution by Type")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    for rect in bars:
        height = rect.get_height()
        ax.annotate(str(int(height)), xy=(rect.get_x() + rect.get_width() / 2, height), xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=7)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)

def _make_timeline_histogram(rows: List[Dict[str, Any]], outpath: str):
    """Generates a timeline histogram of artifact timestamps safely across all OS platforms."""
    valid_dates = []
    for r in rows:
        t = r.get("timestamp") or r.get("last_access")
        if not t:
            continue
        try:
            s = str(t).replace("Z", "").strip()
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo:
                dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            if dt.year >= 1990 and dt.year <= 2040:
                valid_dates.append(dt)
        except Exception:
            continue

    fig, ax = plt.subplots(figsize=(7.0, 3.0), dpi=150)
    if not valid_dates:
        ax.text(0.5, 0.5, "No Timestamped Evidence Available", ha="center", va="center", fontsize=10)
        ax.axis("off")
    else:
        epoch = datetime.datetime(1970, 1, 1)
        timestamps = [(d - epoch).total_seconds() for d in valid_dates]
        ax.hist(timestamps, bins=min(30, max(5, len(set(timestamps)))), color="#0284C7", edgecolor="white", alpha=0.85)
        ax.set_title("Chronological Activity Density (Events Timeline)", fontsize=10, fontweight="bold")
        xlocs = ax.get_xticks()
        if len(xlocs) > 0:
            xlabels = []
            for x in xlocs:
                try:
                    dt_label = epoch + datetime.timedelta(seconds=max(0, x))
                    xlabels.append(dt_label.strftime("%Y-%m-%d\n%H:%M"))
                except Exception:
                    xlabels.append("")
            ax.set_xticks(xlocs)
            ax.set_xticklabels(xlabels, rotation=30, ha="right", fontsize=7)
        ax.set_xlabel("UTC Timestamp", fontsize=8)
        ax.set_ylabel("Events Indexed", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.3)

    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)

def _get_db_conn():
    if open_db:
        return open_db(DB_PATH)
    return sqlite3.connect(DB_PATH)

def parse_target_folder_core(folder_path: str) -> dict:
    r"""
    Intelligently discovers and parses all forensic artifacts within any target directory
    or mounted forensic image drive (e.g. E:\, D:\triage\).
    """
    if not os.path.isdir(folder_path):
        return {"status": "error", "message": f"Target path is not a valid directory: {folder_path}"}

    logger.info(f"Initiating intelligent triage scan on folder: {folder_path}")
    discovered = path_resolver.scan_target_directory(folder_path)
    total_parsed = 0
    all_records = []

    # 1. Prefetch
    for pf in discovered.get("prefetch", []):
        try:
            all_records.extend(prefetch_parser.parse_prefetch(pf))
        except Exception:
            pass

    # 2. LNK Files
    for lnk in discovered.get("lnk", []):
        try:
            all_records.extend(lnk_parser.parse_lnk(lnk))
        except Exception:
            pass

    # 3. Recycle Bin
    for rb in discovered.get("recycle_bin", []):
        try:
            all_records.extend(recycle_parser.parse_i_file(rb))
        except Exception:
            pass

    # 4. PowerShell History
    for ps in discovered.get("powershell_history", []):
        try:
            all_records.extend(powershell_parser.parse_powershell_file(ps))
        except Exception:
            pass

    # 5. Browsers
    for br in discovered.get("browser_history", []):
        try:
            all_records.extend(browser_parser.parse_browser_artifact(br))
        except Exception:
            pass

    # 6. Jump Lists
    for jl in discovered.get("jump_lists", []):
        try:
            all_records.extend(jumplist_parser.parse_jumplist_file(jl))
        except Exception:
            pass

    # 7. Event Logs
    for ev in discovered.get("event_logs", []):
        try:
            all_records.extend(evtx_parser.parse_evtx_file(ev))
        except Exception:
            pass

    # 8. SetupAPI Logs
    for su in discovered.get("usb_devices", []):
        try:
            all_records.extend(usb_parser.parse_setupapi_log(su))
        except Exception:
            pass

    if all_records:
        conn = _get_db_conn()
        try:
            insert_artifacts_bulk(conn, all_records)
            total_parsed = len(all_records)
        finally:
            conn.close()

    summary_msg = f"Triage scan completed on {folder_path}. Extracted and cataloged {total_parsed} forensic artifacts."
    logger.info(summary_msg)
    return {"status": "success", "message": summary_msg, "total_records": total_parsed, "categories_found": list(discovered.keys())}

def parse_live_triage_core() -> dict:
    """
    1-Click Live System Forensic Triage.
    Extracts all available live Windows artifacts: Prefetch, LNKs, Recycle Bin,
    ShellBags, Browser History/Downloads, PowerShell History, UserAssist, USBSTOR,
    BAM/DAM, Startup Autoruns, Jump Lists, and Security Event Logs.
    """
    logger.info("Starting 1-Click Live System Forensic Triage...")
    all_records = []

    # 1. Prefetch
    pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
    if os.path.isdir(pf_dir):
        try:
            for f in os.listdir(pf_dir):
                if f.lower().endswith(".pf"):
                    all_records.extend(prefetch_parser.parse_prefetch(os.path.join(pf_dir, f)))
        except Exception as e:
            logger.warning(f"Live Prefetch scan notice: {e}")

    # 2. LNK Files (Recent & Desktop)
    recent_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent")
    if os.path.isdir(recent_dir):
        try:
            for f in os.listdir(recent_dir):
                if f.lower().endswith(".lnk"):
                    all_records.extend(lnk_parser.parse_lnk(os.path.join(recent_dir, f)))
        except Exception:
            pass

    # 3. Recycle Bin
    recycle_root = os.path.join(os.environ.get("SystemDrive", "C:"), r"\$Recycle.Bin")
    if os.path.isdir(recycle_root):
        try:
            for root, _, files in os.walk(recycle_root):
                for f in files:
                    if f.lower().startswith("$i") or f.lower().startswith("i"):
                        all_records.extend(recycle_parser.parse_i_file(os.path.join(root, f)))
        except Exception:
            pass

    # 4. ShellBags (Registry)
    try:
        all_records.extend(shellbags_parser.parse_shellbags())
    except Exception as e:
        logger.warning(f"ShellBags parse notice: {e}")

    # 5. Web Browsers (Chrome, Edge, Brave, Opera, Firefox)
    try:
        all_records.extend(browser_parser.parse_all_live_browsers())
    except Exception as e:
        logger.warning(f"Browser parse notice: {e}")

    # 6. PowerShell History
    try:
        all_records.extend(powershell_parser.parse_all_live_powershell())
    except Exception as e:
        logger.warning(f"PowerShell parse notice: {e}")

    # 7. UserAssist (Registry ROT13)
    try:
        all_records.extend(userassist_parser.parse_live_userassist())
    except Exception as e:
        logger.warning(f"UserAssist parse notice: {e}")

    # 8. USB & Removable Storage
    try:
        all_records.extend(usb_parser.parse_live_usbstor())
    except Exception as e:
        logger.warning(f"USBSTOR parse notice: {e}")

    # 9. BAM / DAM (Background Activity Moderator)
    try:
        all_records.extend(bam_parser.parse_live_bam())
    except Exception as e:
        logger.warning(f"BAM parse notice: {e}")

    # 10. Startup & Persistence Autoruns
    try:
        all_records.extend(startup_parser.parse_live_startup())
    except Exception as e:
        logger.warning(f"Startup parse notice: {e}")

    # 11. Jump Lists
    try:
        all_records.extend(jumplist_parser.parse_live_jumplists())
    except Exception as e:
        logger.warning(f"JumpLists parse notice: {e}")

    # 12. Security & Windows Event Logs
    try:
        all_records.extend(evtx_parser.parse_live_event_logs())
    except Exception as e:
        logger.warning(f"EVTX parse notice: {e}")

    # Commit to DB
    if all_records:
        conn = _get_db_conn()
        try:
            insert_artifacts_bulk(conn, all_records)
        finally:
            conn.close()

    msg = f"Live Triage complete! Successfully captured and indexed {len(all_records)} forensic artifacts."
    logger.info(msg)
    return {"status": "success", "message": msg, "count": len(all_records)}

def parse_preset_core(preset_id: str) -> dict:
    """
    Parses a specific preset forensic category.
    """
    records = []
    pid = preset_id.lower()

    if pid == "all_triage":
        return parse_live_triage_core()
    elif pid == "execution_persistence":
        pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        if os.path.isdir(pf_dir):
            for f in os.listdir(pf_dir):
                if f.lower().endswith(".pf"):
                    records.extend(prefetch_parser.parse_prefetch(os.path.join(pf_dir, f)))
        records.extend(userassist_parser.parse_live_userassist())
        records.extend(bam_parser.parse_live_bam())
        records.extend(startup_parser.parse_live_startup())
    elif pid == "file_access":
        recent_dir = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent")
        if os.path.isdir(recent_dir):
            for f in os.listdir(recent_dir):
                if f.lower().endswith(".lnk"):
                    records.extend(lnk_parser.parse_lnk(os.path.join(recent_dir, f)))
        records.extend(shellbags_parser.parse_shellbags())
        records.extend(jumplist_parser.parse_live_jumplists())
    elif pid == "browser_downloads":
        records.extend(browser_parser.parse_all_live_browsers())
    elif pid == "powershell_cli":
        records.extend(powershell_parser.parse_all_live_powershell())
    elif pid == "usb_storage":
        records.extend(usb_parser.parse_live_usbstor())
    elif pid == "event_logs":
        records.extend(evtx_parser.parse_live_event_logs())
    else:
        return {"status": "error", "message": f"Unknown preset ID: {preset_id}"}

    if records:
        conn = _get_db_conn()
        try:
            insert_artifacts_bulk(conn, records)
        finally:
            conn.close()

    return {"status": "success", "message": f"Preset '{preset_id}' processed {len(records)} entries.", "count": len(records)}

def get_stats_core() -> Dict[str, Any]:
    """
    Computes summary metrics for forensic dashboard visualization.
    """
    rows = get_all_artifacts_json()
    total_count = len(rows)

    type_counts = {}
    anomaly_count = 0
    unique_programs = set()

    for r in rows:
        t = r.get("artifact_type") or "unknown"
        type_counts[t] = type_counts.get(t, 0) + 1
        extra = r.get("extra") or ""
        if "threat_tag" in extra or "CRITICAL" in extra or "1102" in extra or "TAMPERING" in extra:
            anomaly_count += 1
        if t in ("prefetch", "userassist", "bam_execution"):
            name = r.get("name")
            if name:
                unique_programs.add(name)

    return {
        "total_artifacts": total_count,
        "anomalies_detected": anomaly_count,
        "unique_executables": len(unique_programs),
        "type_breakdown": type_counts,
        "db_sha256": _sha256_file(DB_PATH)
    }

def get_all_artifacts_json() -> List[Dict[str, Any]]:
    """Fetches all artifacts ordered by timestamp."""
    if query_artifacts is None:
        return []
    rows = query_artifacts(DB_PATH)
    for row in rows:
        for k, v in row.items():
            if isinstance(v, datetime.datetime):
                row[k] = v.isoformat()
    return rows

def clear_database_core() -> dict:
    if clear_database is None:
        return {"status": "error", "message": "Clear database function unavailable."}
    try:
        clear_database(DB_PATH)
        return {"status": "success", "message": "Database cleared successfully."}
    except Exception as e:
        return {"status": "error", "message": f"Error clearing database: {e}"}

def generate_csv_report(file_path: str) -> dict:
    rows = get_all_artifacts_json()
    if not rows:
        return {"status": "info", "message": "No artifacts to export."}
    try:
        headers = list(rows[0].keys())
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        return {"status": "success", "message": f"CSV report exported: {file_path}"}
    except Exception as e:
        return {"status": "error", "message": f"CSV export error: {e}"}

def export_json_report(file_path: str) -> dict:
    rows = get_all_artifacts_json()
    metadata = build_metadata(DB_PATH)
    data = {
        "metadata": metadata,
        "total_records": len(rows),
        "artifacts": rows
    }
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return {"status": "success", "message": f"JSON timeline report exported: {file_path}"}
    except Exception as e:
        return {"status": "error", "message": f"JSON export error: {e}"}

def generate_pdf_report_core(file_path: str, report_details: Dict[str, Any]) -> dict:
    if report_gen is None:
        return {"status": "error", "message": "PDF report generator unavailable."}
    try:
        rows = get_all_artifacts_json()
        metadata = build_metadata(DB_PATH)
        metadata["Case ID"] = report_details.get("caseNumber", "")
        metadata["Evidence ID"] = report_details.get("evidenceNumber", "")
        metadata["Description"] = report_details.get("uniqueDescription", "")
        metadata["Examiner"] = report_details.get("examiner", metadata.get("Examiner", ""))
        metadata["Notes"] = report_details.get("notes", "")

        tmp_dir = tempfile.mkdtemp(prefix="wab_pdf_")
        counts_png = os.path.join(tmp_dir, "counts.png")
        timeline_png = os.path.join(tmp_dir, "timeline.png")

        _make_counts_chart(rows, counts_png)
        _make_timeline_histogram(rows, timeline_png)

        metadata["chart_counts"] = counts_png
        metadata["chart_timeline"] = timeline_png

        report_gen.generate_pdf_report(DB_PATH, file_path, title=f"Windows Forensics Audit Report ({socket.gethostname()})", metadata=metadata)
        return {"status": "success", "message": f"PDF report generated: {file_path}"}
    except Exception as e:
        return {"status": "error", "message": f"PDF generation error: {e}"}
    finally:
        if "tmp_dir" in locals() and os.path.exists(tmp_dir):
            try:
                for f in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, f))
                os.rmdir(tmp_dir)
            except Exception:
                pass

def generate_correlation_pdf_core(file_path: str, report_details: Dict[str, Any]) -> dict:
    if report_gen is None:
        return {"status": "error", "message": "Report generation module not available."}
    try:
        rows = get_all_artifacts_json()
        metadata = build_metadata(DB_PATH)
        metadata["Case ID"] = report_details.get("caseNumber", "")
        metadata["Evidence ID"] = report_details.get("evidenceNumber", "")
        metadata["Description"] = report_details.get("uniqueDescription", "")
        metadata["Examiner"] = report_details.get("examiner", metadata.get("Examiner", ""))
        metadata["Notes"] = report_details.get("notes", "")

        tmp_dir = tempfile.mkdtemp(prefix="wab_corr_")
        counts_png = os.path.join(tmp_dir, "counts_corr.png")
        timeline_png = os.path.join(tmp_dir, "timeline_corr.png")

        _make_counts_chart(rows, counts_png)
        _make_timeline_histogram(rows, timeline_png)

        metadata["chart_counts"] = counts_png
        metadata["chart_timeline"] = timeline_png

        report_gen.generate_correlation_pdf(DB_PATH, file_path, title=f"Session Correlation & Timeline Report ({socket.gethostname()})", metadata=metadata)
        return {"status": "success", "message": f"Correlation PDF report generated: {file_path}"}
    except Exception as e:
        return {"status": "error", "message": f"Correlation PDF error: {e}"}
    finally:
        if "tmp_dir" in locals() and os.path.exists(tmp_dir):
            try:
                for f in os.listdir(tmp_dir):
                    os.remove(os.path.join(tmp_dir, f))
                os.rmdir(tmp_dir)
            except Exception:
                pass

def get_correlations_json() -> List[Dict[str, Any]]:
    if correlate_artifacts is None:
        return []
    try:
        return correlate_artifacts(DB_PATH)
    except Exception as e:
        logger.error(f"Correlation error: {e}")
        return []

if init_db:
    init_db(DB_PATH)
