# app.py
"""
Flask REST API & Web Server for Windows Forensic Artifacts Parser.
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import threading
import uuid
import datetime
import logging
import tempfile
import shutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

import core_logic
from parsers import path_resolver

app = Flask(__name__, static_folder="web", template_folder="web", static_url_path="")

# In-memory store for async background tasks
tasks = {}

def run_in_background(task_id, func, *args, **kwargs):
    tasks[task_id] = {"status": "in_progress", "message": "Task processing...", "progress": 0}
    try:
        result = func(*args, **kwargs)
        tasks[task_id]["status"] = "completed"
        tasks[task_id]["message"] = result.get("message", "Task completed.")
        tasks[task_id]["result"] = result
    except Exception as e:
        logger.exception(f"Background task {task_id} failed: {e}")
        tasks[task_id]["status"] = "failed"
        tasks[task_id]["message"] = str(e)
        tasks[task_id]["error"] = str(e)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/correlation")
def correlation():
    return render_template("correlation.html")

@app.route("/api/presets", methods=["GET"])
def api_get_presets():
    """Returns artifact catalog and preset list for UI selectors."""
    return jsonify({
        "presets": path_resolver.get_presets(),
        "catalog": path_resolver.get_catalog()
    }), 200

@app.route("/api/stats", methods=["GET"])
def api_get_stats():
    """Returns summary forensic metrics for dashboard visual cards."""
    try:
        stats = core_logic.get_stats_core()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/live_triage", methods=["POST"])
def api_live_triage():
    """Triggers 1-Click full live triage in the background."""
    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_live_triage_core)).start()
    return jsonify({
        "status": "success",
        "message": "Live system forensic triage initiated in background.",
        "task_id": task_id
    }), 202

@app.route("/api/parse_target", methods=["POST"])
def api_parse_target():
    """Triggers intelligent auto-discovery scan on a target directory or mounted image."""
    data = request.get_json() or {}
    folder_path = data.get("folder_path", "").strip()

    if not folder_path:
        return jsonify({"status": "error", "message": "No folder_path provided."}), 400
    if not os.path.isdir(folder_path):
        return jsonify({"status": "error", "message": f"Target path is not a valid directory: {folder_path}"}), 400

    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_target_folder_core, folder_path)).start()
    return jsonify({
        "status": "success",
        "message": f"Triage scan initiated for '{folder_path}' in background.",
        "task_id": task_id
    }), 202

@app.route("/api/parse_preset", methods=["POST"])
def api_parse_preset():
    """Parses a selected preset category."""
    data = request.get_json() or {}
    preset_id = data.get("preset_id", "").strip()
    if not preset_id:
        return jsonify({"status": "error", "message": "No preset_id provided."}), 400

    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_preset_core, preset_id)).start()
    return jsonify({
        "status": "success",
        "message": f"Preset '{preset_id}' parsing initiated in background.",
        "task_id": task_id
    }), 202

@app.route("/api/parse_folder", methods=["POST"])
def api_parse_folder():
    """Backwards compatibility for legacy parse_folder calls."""
    data = request.get_json() or {}
    folder_path = data.get("folder_path", "").strip()
    if not folder_path:
        return jsonify({"status": "error", "message": "No folder_path provided."}), 400
    if not os.path.isdir(folder_path):
        return jsonify({"status": "error", "message": f"Invalid folder path: {folder_path}"}), 400

    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_target_folder_core, folder_path)).start()
    return jsonify({"status": "success", "message": "Parsing initiated in background.", "task_id": task_id}), 202

@app.route("/api/parse_shellbags", methods=["POST"])
def api_parse_shellbags():
    task_id = str(uuid.uuid4())
    threading.Thread(target=run_in_background, args=(task_id, core_logic.parse_preset_core, "file_access")).start()
    return jsonify({"status": "success", "message": "Explorer file access parsing initiated.", "task_id": task_id}), 202

@app.route("/api/artifacts", methods=["GET"])
def api_get_artifacts():
    try:
        artifacts = core_logic.get_all_artifacts_json()
        return jsonify(artifacts), 200
    except Exception as e:
        logger.exception("Error fetching artifacts:")
        return jsonify({"status": "error", "message": f"Failed to fetch artifacts: {str(e)}"}), 500

@app.route("/api/clear_db", methods=["POST"])
def api_clear_db():
    try:
        result = core_logic.clear_database_core()
        return jsonify(result), 200
    except Exception as e:
        logger.exception("Error clearing database:")
        return jsonify({"status": "error", "message": f"Failed to clear database: {str(e)}"}), 500

@app.route("/api/export_csv", methods=["GET"])
def api_export_csv():
    temp_dir = None
    response = None
    try:
        filename = f"artifacts_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)

        result = core_logic.generate_csv_report(filepath)
        if result["status"] == "success":
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        logger.exception("Error exporting CSV:")
        return jsonify({"status": "error", "message": f"Failed to export CSV: {str(e)}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, "call_on_close")):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

@app.route("/api/export_json", methods=["GET"])
def api_export_json():
    temp_dir = None
    response = None
    try:
        filename = f"artifacts_timeline_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)

        result = core_logic.export_json_report(filepath)
        if result["status"] == "success":
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, "call_on_close")):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

@app.route("/api/export_pdf", methods=["POST"])
def api_export_pdf():
    report_details = request.get_json() or {}
    temp_dir = None
    response = None
    try:
        filename = f"forensics_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)

        result = core_logic.generate_pdf_report_core(filepath, report_details)
        if result["status"] == "success":
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        logger.exception("Error exporting PDF report:")
        return jsonify({"status": "error", "message": f"Failed to export PDF: {str(e)}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, "call_on_close")):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

@app.route("/api/correlations", methods=["GET"])
def api_get_correlations():
    try:
        correlations = core_logic.get_correlations_json()
        return jsonify(correlations), 200
    except Exception as e:
        logger.exception("Error fetching correlations:")
        return jsonify({"status": "error", "message": f"Failed to fetch correlations: {str(e)}"}), 500

@app.route("/api/export_correlation_pdf", methods=["POST"])
def api_export_correlation_pdf():
    report_details = request.get_json() or {}
    temp_dir = None
    response = None
    try:
        filename = f"correlation_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        temp_dir = tempfile.mkdtemp()
        filepath = os.path.join(temp_dir, filename)

        result = core_logic.generate_correlation_pdf_core(filepath, report_details)
        if result["status"] == "success":
            response = send_file(filepath, as_attachment=True, download_name=filename)
            @response.call_on_close
            def cleanup_file():
                try:
                    shutil.rmtree(temp_dir)
                except Exception:
                    pass
            return response
        else:
            return jsonify(result), 500
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to export correlation PDF: {str(e)}"}), 500
    finally:
        if temp_dir and os.path.exists(temp_dir) and (response is None or not hasattr(response, "call_on_close")):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass

@app.route("/api/task_status/<task_id>", methods=["GET"])
def api_task_status(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"status": "error", "message": "Task not found."}), 404
    return jsonify(task)

if __name__ == "__main__":
    app.run(debug=True, port=5000)