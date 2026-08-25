# main.py
r"""
Footprint Analyzer - Windows Forensic Artifacts Parser & Activity Reconstruction Workstation.
Enterprise-grade native forensic workstation featuring:
- ⏱️ Reconstructed User Activity Timeline & Cross-Artifact Correlation with MITRE ATT&CK Mapping
- 📋 Autopsy-style Hierarchical Evidence Tree & Searchable Master Grid
- 📊 Embedded Visual Forensics & Analytics Dashboard (Matplotlib)
- 📖 Forensic Artifact Catalog & Live Path Resolver
- Neat, clean, cyber-slate theme with unified branding and zero redundant controls
"""

import os
import sys
import sqlite3
import threading
import json
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, List, Any, Optional

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

try:
    from db.db_utils import open_db
    from db.schema import init_db, query_artifacts, clear_database
except ImportError:
    from db_utils import open_db
    from schema import init_db, query_artifacts, clear_database

from parsers import path_resolver
from correlator import correlate_artifacts
import core_logic

DB_PATH = "artifacts.db"
TOOL_VERSION = "v1.3.4"

# Unified Cyber-Slate Theme (Matching Web Dashboard)
THEME = {
    "bg_base": "#0D1117",        # Deep GitHub/Obsidian Slate Base
    "bg_surface": "#161B22",     # Elevated Card Panel
    "bg_elevated": "#21262D",    # Active Control Background
    "bg_highlight": "#30363D",   # Hover / Highlight
    "bg_selected": "#1F6FEB",    # Vibrant Sapphire Blue Selection
    "text_primary": "#F0F6FC",   # Crisp Pure White Text
    "text_secondary": "#8B949E", # Slate Gray Text
    "text_muted": "#6E7681",     # Muted Slate
    "accent_blue": "#58A6FF",    # Sapphire Blue
    "accent_green": "#3FB950",   # Emerald Green
    "accent_purple": "#BC8CFF",  # Violet Purple
    "accent_amber": "#D29922",   # Amber
    "accent_threat": "#F85149",  # Alert Crimson Red
    "accent_threat_bg": "#2E1214",
    "border": "#30363D",         # Clean 1px Border
}

FONT_TITLE = ("Segoe UI", 11, "bold")
FONT_TAB = ("Segoe UI", 9, "bold")
FONT_HEADING = ("Segoe UI", 9, "bold")
FONT_REGULAR = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 9, "bold")
FONT_SMALL = ("Segoe UI", 8)
FONT_MONO = ("Consolas", 9)
FONT_MONO_BOLD = ("Consolas", 9, "bold")

class WinActivityReconApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Windows User Activity Reconstruction Tool (v1.3.5)")
        self.geometry("1380x850")
        self.minsize(1080, 700)
        
        # State
        self.all_artifacts: List[Dict[str, Any]] = []
        self.filtered_artifacts: List[Dict[str, Any]] = []
        self.all_correlations: List[Dict[str, Any]] = []
        self.filtered_correlations: List[Dict[str, Any]] = []
        self.active_category: str = "all"
        self.sort_column: str = "id"
        self.sort_ascending: bool = False
        self.timeline_anomalies_only: bool = False
        
        init_db(DB_PATH)
        self._configure_styles()
        self._build_menu()
        self._build_ui()
        self.refresh_evidence_data()

    def _configure_styles(self):
        self.configure(background=THEME["bg_base"])
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Global Config
        style.configure(".", background=THEME["bg_base"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("TFrame", background=THEME["bg_base"])
        style.configure("Surface.TFrame", background=THEME["bg_surface"])
        style.configure("Elevated.TFrame", background=THEME["bg_elevated"])
        style.configure("TLabel", background=THEME["bg_base"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("Surface.TLabel", background=THEME["bg_surface"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("Muted.TLabel", background=THEME["bg_surface"], foreground=THEME["text_muted"], font=FONT_SMALL)
        style.configure("Header.TLabel", font=FONT_TITLE, foreground=THEME["text_primary"], background=THEME["bg_surface"])

        # Styled Buttons
        style.configure("TButton", background=THEME["bg_elevated"], foreground=THEME["text_primary"], borderwidth=1, bordercolor=THEME["border"], padding=(8, 5), font=FONT_BOLD)
        style.map("TButton", background=[("active", THEME["bg_highlight"]), ("hover", THEME["bg_highlight"])], foreground=[("active", THEME["accent_blue"])])

        # Primary Live Triage (Emerald Green)
        style.configure("Primary.TButton", background="#238636", foreground="#FFFFFF", font=FONT_BOLD, borderwidth=0, padding=(10, 5))
        style.map("Primary.TButton", background=[("active", "#2EA043"), ("hover", "#2EA043")], foreground=[("active", "#FFFFFF"), ("hover", "#FFFFFF")])

        # Action / Export (Sapphire Blue)
        style.configure("Action.TButton", background="#1F6FEB", foreground="#FFFFFF", font=FONT_BOLD, borderwidth=0, padding=(10, 5))
        style.map("Action.TButton", background=[("active", "#388BFD"), ("hover", "#388BFD")], foreground=[("active", "#FFFFFF"), ("hover", "#FFFFFF")])

        # Danger (Crimson Red)
        style.configure("Danger.TButton", background=THEME["bg_elevated"], foreground=THEME["accent_threat"], font=FONT_BOLD, borderwidth=1, bordercolor=THEME["border"], padding=(8, 5))
        style.map("Danger.TButton", background=[("active", THEME["accent_threat_bg"]), ("hover", THEME["accent_threat_bg"])], foreground=[("active", THEME["accent_threat"])])

        # Inputs & Comboboxes
        style.configure("TEntry", fieldbackground=THEME["bg_elevated"], foreground=THEME["text_primary"], insertcolor=THEME["accent_blue"], bordercolor=THEME["border"], padding=5, font=FONT_REGULAR)
        style.configure("TCombobox", fieldbackground=THEME["bg_elevated"], foreground=THEME["text_primary"], selectbackground=THEME["bg_highlight"], selectforeground=THEME["text_primary"], bordercolor=THEME["border"], font=FONT_REGULAR)
        style.map("TCombobox", fieldbackground=[("readonly", THEME["bg_elevated"])], foreground=[("readonly", THEME["text_primary"])])

        # Treeview / Data Grid
        style.configure("Treeview", background=THEME["bg_surface"], fieldbackground=THEME["bg_surface"], foreground=THEME["text_primary"], rowheight=30, borderwidth=0, font=FONT_REGULAR)
        style.map("Treeview", background=[("selected", THEME["bg_selected"])], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=THEME["bg_elevated"], foreground=THEME["text_secondary"], font=FONT_HEADING, bordercolor=THEME["border"], padding=5)
        style.map("Treeview.Heading", background=[("active", THEME["bg_highlight"])], foreground=[("active", THEME["accent_blue"])])

        # Notebook Tabs
        style.configure("Main.TNotebook", background=THEME["bg_surface"], borderwidth=0)
        style.configure("Main.TNotebook.Tab", background=THEME["bg_elevated"], foreground=THEME["text_secondary"], padding=(14, 6), font=FONT_TAB)
        style.map("Main.TNotebook.Tab", background=[("selected", "#1F6FEB")], foreground=[("selected", "#FFFFFF")])

    def _build_menu(self):
        menubar = tk.Menu(self, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["accent_blue"], font=FONT_REGULAR)
        
        file_menu = tk.Menu(menubar, tearoff=0, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["accent_blue"])
        file_menu.add_command(label="⚡ 1-Click Live Triage", command=self.action_live_triage)
        file_menu.add_command(label="🔍 Auto-Scan Target Folder...", command=self.action_browse_target)
        file_menu.add_separator()
        file_menu.add_command(label="🔄 Refresh Dataset", command=self.refresh_evidence_data, accelerator="F5")
        file_menu.add_command(label="🗑️ Clear Evidence Database", command=self.action_clear_db, accelerator="Ctrl+Del")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        export_menu = tk.Menu(menubar, tearoff=0, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["accent_blue"])
        export_menu.add_command(label="📑 Export Executive PDF Audit Report...", command=self.action_export_pdf)
        export_menu.add_command(label="⏱️ Export Correlation PDF Report...", command=self.action_export_corr_pdf)
        export_menu.add_command(label="📄 Export Standard CSV Timeline...", command=self.action_export_csv)
        export_menu.add_command(label="📦 Export DFIR JSON Timeline...", command=self.action_export_json)
        menubar.add_cascade(label="Export", menu=export_menu)

        self.config(menu=menubar)
        self.bind("<F5>", lambda e: self.refresh_evidence_data())
        self.bind("<Control-Delete>", lambda e: self.action_clear_db())

    def _build_ui(self):
        master_frame = ttk.Frame(self)
        master_frame.pack(fill=tk.BOTH, expand=True)

        # 1. TOP HEADER & TELEMETRY
        header = ttk.Frame(master_frame, style="Surface.TFrame", padding=(16, 8))
        header.pack(fill=tk.X)

        hdr_left = ttk.Frame(header, style="Surface.TFrame")
        hdr_left.pack(side=tk.LEFT)
        ttk.Label(hdr_left, text="🛡️ WINACTIVITY RECON", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr_left, text=" | Windows User Activity Reconstruction & Forensic Workstation", font=FONT_REGULAR, foreground=THEME["text_secondary"], background=THEME["bg_surface"]).pack(side=tk.LEFT, padx=8)

        hdr_right = ttk.Frame(header, style="Surface.TFrame")
        hdr_right.pack(side=tk.RIGHT)
        self.status_indicator = ttk.Label(hdr_right, text="● Ready", font=FONT_REGULAR, foreground=THEME["accent_green"], background=THEME["bg_surface"])
        self.status_indicator.pack(side=tk.LEFT, padx=8)

        self.db_sha_label = ttk.Label(hdr_right, text="DB SHA: -", font=FONT_MONO, foreground=THEME["accent_blue"], background=THEME["bg_elevated"], padding=(6, 2))
        self.db_sha_label.pack(side=tk.LEFT, padx=4)

        # 2. STREAMLINED COMMAND BAR
        acq_bar = ttk.Frame(master_frame, style="Elevated.TFrame", padding=(10, 8))
        acq_bar.pack(fill=tk.X, padx=6, pady=(2, 2))

        ttk.Button(acq_bar, text="⚡ 1-Click Live Triage", style="Primary.TButton", command=self.action_live_triage).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(acq_bar, text="Preset:", background=THEME["bg_elevated"], foreground=THEME["text_muted"], font=FONT_HEADING).pack(side=tk.LEFT, padx=(4, 2))
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(acq_bar, textvariable=self.preset_var, width=28, state="readonly", font=FONT_REGULAR)
        self.preset_combo["values"] = [
            "⚡ Full Live Triage (All Artifacts)",
            "🚀 Program Execution & Persistence",
            "📁 File & Folder Access",
            "🌐 Web Browsers & Downloads",
            "💻 PowerShell CLI History",
            "🔌 USB Storage Devices",
            "🛡️ Security & Windows Event Logs"
        ]
        self.preset_combo.current(0)
        self.preset_combo.pack(side=tk.LEFT, padx=2)
        ttk.Button(acq_bar, text="Run", command=self.action_run_preset).pack(side=tk.LEFT, padx=(0, 10))

        self.target_path_var = tk.StringVar()
        target_entry = ttk.Entry(acq_bar, textvariable=self.target_path_var, width=24)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 2))
        ttk.Button(acq_bar, text="Browse...", command=self.action_browse_target).pack(side=tk.LEFT, padx=2)
        ttk.Button(acq_bar, text="Scan Target", command=self.action_scan_target).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(acq_bar, text="🗑️ Clear DB", style="Danger.TButton", command=self.action_clear_db).pack(side=tk.RIGHT, padx=3)
        ttk.Button(acq_bar, text="📑 Export PDF", style="Action.TButton", command=self.action_export_pdf).pack(side=tk.RIGHT, padx=3)
        ttk.Button(acq_bar, text="🔄 Refresh", command=self.refresh_evidence_data).pack(side=tk.RIGHT, padx=3)

        # 3. PRIMARY NOTEBOOK
        self.main_notebook = ttk.Notebook(master_frame, style="Main.TNotebook")
        self.main_notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # TAB 1: ⏱️ RECONSTRUCTED TIMELINE & CORRELATION
        tab_timeline = ttk.Frame(self.main_notebook, style="Surface.TFrame")
        self.main_notebook.add(tab_timeline, text="⏱️ Activity Reconstruction Timeline")
        self._build_timeline_tab(tab_timeline)

        # TAB 2: 📋 MASTER EVIDENCE GRID & SUBSECTIONS
        tab_evidence = ttk.Frame(self.main_notebook, style="Surface.TFrame")
        self.main_notebook.add(tab_evidence, text="📋 Evidence Master Grid")
        self._build_evidence_tab(tab_evidence)

        # TAB 3: 📊 VISUAL ANALYTICS
        tab_analytics = ttk.Frame(self.main_notebook, style="Surface.TFrame")
        self.main_notebook.add(tab_analytics, text="📊 Visual Analytics Dashboard")
        self._build_analytics_tab(tab_analytics)

        # TAB 4: 📖 ARTIFACT CATALOG
        tab_catalog = ttk.Frame(self.main_notebook, style="Surface.TFrame")
        self.main_notebook.add(tab_catalog, text="📖 Artifact Catalog & Paths")
        self._build_catalog_tab(tab_catalog)

    # -------------------------------------------------------------
    # BUILD TAB 1: CORRELATION & ACTIVITY TIMELINE
    # -------------------------------------------------------------
    def _build_timeline_tab(self, parent):
        ctrl_bar = ttk.Frame(parent, style="Elevated.TFrame", padding=(10, 6))
        ctrl_bar.pack(fill=tk.X)

        self.btn_tl_all = ttk.Button(ctrl_bar, text="All Events", style="Action.TButton", command=self._timeline_filter_all)
        self.btn_tl_all.pack(side=tk.LEFT, padx=(0, 4))

        self.btn_tl_anomalies = ttk.Button(ctrl_bar, text="🚨 Anomalies Only", command=self._timeline_filter_anomalies)
        self.btn_tl_anomalies.pack(side=tk.LEFT, padx=4)

        ttk.Label(ctrl_bar, text="Search:", background=THEME["bg_elevated"], foreground=THEME["text_muted"], font=FONT_HEADING).pack(side=tk.LEFT, padx=(12, 2))
        self.timeline_search_var = tk.StringVar()
        self.timeline_search_var.trace_add("write", lambda *args: self._filter_timeline_table())
        tl_search_entry = ttk.Entry(ctrl_bar, textvariable=self.timeline_search_var, width=32)
        tl_search_entry.pack(side=tk.LEFT, padx=2)

        ttk.Button(ctrl_bar, text="Export Correlation PDF", command=self.action_export_corr_pdf).pack(side=tk.RIGHT, padx=2)

        self.tl_count_label = ttk.Label(ctrl_bar, text="0 Events", font=FONT_REGULAR, background=THEME["bg_elevated"], foreground=THEME["accent_blue"])
        self.tl_count_label.pack(side=tk.RIGHT, padx=8)

        # Timeline Paned Window
        tl_paned = ttk.PanedWindow(parent, orient=tk.VERTICAL)
        tl_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        grid_frame = ttk.Frame(tl_paned)
        tl_paned.add(grid_frame, weight=3)

        cols = ("time", "session", "type", "detail", "anomaly", "mitre")
        self.timeline_tree = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        
        headers = {
            "time": ("Timestamp (UTC)", 155),
            "session": ("Session", 75),
            "type": ("Artifact Type", 140),
            "detail": ("Action Detail", 460),
            "anomaly": ("Anomaly / Threat Indicator", 180),
            "mitre": ("MITRE ATT&CK", 130)
        }
        for k, (txt, w) in headers.items():
            self.timeline_tree.heading(k, text=txt)
            self.timeline_tree.column(k, width=w)

        self.timeline_tree.tag_configure("anomaly", background=THEME["accent_threat_bg"], foreground="#FCA5A5")
        self.timeline_tree.tag_configure("normal", foreground=THEME["text_primary"])

        vsb = ttk.Scrollbar(grid_frame, orient=tk.VERTICAL, command=self.timeline_tree.yview)
        hsb = ttk.Scrollbar(grid_frame, orient=tk.HORIZONTAL, command=self.timeline_tree.xview)
        self.timeline_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.timeline_tree.pack(fill=tk.BOTH, expand=True)
        self.timeline_tree.bind("<<TreeviewSelect>>", self._on_timeline_select)

        # Bottom Detail Inspector
        tl_detail_frame = ttk.Frame(tl_paned, style="Elevated.TFrame", padding=8)
        tl_paned.add(tl_detail_frame, weight=1)

        ttk.Label(tl_detail_frame, text="EVENT DEEP DIVE & MITRE CONTEXT", font=FONT_HEADING, foreground=THEME["accent_blue"], background=THEME["bg_elevated"]).pack(anchor=tk.W, pady=(0, 2))
        self.tl_detail_txt = tk.Text(tl_detail_frame, height=4, background=THEME["bg_surface"], foreground=THEME["text_primary"], insertbackground=THEME["accent_blue"], borderwidth=0, font=FONT_MONO, wrap=tk.WORD)
        self.tl_detail_txt.pack(fill=tk.BOTH, expand=True)

    def _timeline_filter_all(self):
        self.timeline_anomalies_only = False
        self.btn_tl_all.configure(style="Action.TButton")
        self.btn_tl_anomalies.configure(style="TButton")
        self._filter_timeline_table()

    def _timeline_filter_anomalies(self):
        self.timeline_anomalies_only = True
        self.btn_tl_anomalies.configure(style="Action.TButton")
        self.btn_tl_all.configure(style="TButton")
        self._filter_timeline_table()

    def _filter_timeline_table(self):
        q = self.timeline_search_var.get().strip().lower()
        self.filtered_correlations = []

        for c in self.all_correlations:
            if self.timeline_anomalies_only and not c.get("anomaly"):
                continue
            if q:
                match_blob = f"{c.get('timestamp', '')} {c.get('artifact_type', '')} {c.get('detail', '')} {c.get('anomaly', '')} {c.get('mitre', '')}".lower()
                if q not in match_blob:
                    continue
            self.filtered_correlations.append(c)

        for r in self.timeline_tree.get_children():
            self.timeline_tree.delete(r)

        self.tl_count_label.config(text=f"Showing {len(self.filtered_correlations):,} of {len(self.all_correlations):,} events")

        for idx, item in enumerate(self.filtered_correlations):
            has_anomaly = bool(item.get("anomaly"))
            tag = "anomaly" if has_anomaly else "normal"
            self.timeline_tree.insert("", tk.END, iid=str(idx), values=(
                item.get("timestamp"),
                f"S-{item.get('session', 1)}",
                item.get("artifact_type"),
                item.get("detail"),
                item.get("anomaly") or "Normal",
                item.get("mitre") or "-"
            ), tags=(tag,))

    def _on_timeline_select(self, event):
        sel = self.timeline_tree.selection()
        if not sel: return
        idx = int(sel[0])
        if idx < len(self.filtered_correlations):
            it = self.filtered_correlations[idx]
            txt = f"Timestamp (UTC): {it.get('timestamp')}\n"
            txt += f"Session: Session {it.get('session', 1)}\n"
            txt += f"Type: {it.get('artifact_type')}\n"
            txt += f"Action: {it.get('detail')}\n"
            if it.get("anomaly"):
                txt += f"\n🚨 ANOMALY: {it.get('anomaly')}\n"
            if it.get("mitre"):
                txt += f"🛡️ MITRE ATT&CK: {it.get('mitre')}\n"
            self.tl_detail_txt.delete("1.0", tk.END)
            self.tl_detail_txt.insert(tk.END, txt)

    # -------------------------------------------------------------
    # BUILD TAB 2: EVIDENCE MASTER GRID WITH HIERARCHICAL TREE
    # -------------------------------------------------------------
    def _build_evidence_tab(self, parent):
        workspace = ttk.Frame(parent)
        workspace.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # LEFT SIDEBAR
        sidebar_frame = ttk.Frame(workspace, style="Surface.TFrame", width=250)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        sidebar_frame.pack_propagate(False)

        sb_header = ttk.Frame(sidebar_frame, style="Elevated.TFrame", padding=(8, 6))
        sb_header.pack(fill=tk.X)
        ttk.Label(sb_header, text="EVIDENCE CATEGORIES", font=FONT_HEADING, foreground=THEME["text_secondary"], background=THEME["bg_elevated"]).pack(side=tk.LEFT)
        self.sidebar_total_badge = ttk.Label(sb_header, text="0", font=FONT_MONO_BOLD, foreground="#FFFFFF", background=THEME["bg_selected"], padding=(4, 1))
        self.sidebar_total_badge.pack(side=tk.RIGHT)

        self.tree_categories = ttk.Treeview(sidebar_frame, show="tree", selectmode="browse")
        self.tree_categories.pack(fill=tk.BOTH, expand=True, padx=2, pady=4)
        self.tree_categories.bind("<<TreeviewSelect>>", self._on_category_select)
        self._populate_hierarchical_category_tree()

        # RIGHT MAIN PANE
        paned = ttk.PanedWindow(workspace, orient=tk.VERTICAL)
        paned.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        table_container = ttk.Frame(paned, style="Surface.TFrame")
        paned.add(table_container, weight=3)

        search_bar = ttk.Frame(table_container, style="Surface.TFrame", padding=(6, 4))
        search_bar.pack(fill=tk.X)

        ttk.Label(search_bar, text="Search:", background=THEME["bg_surface"], font=FONT_HEADING, foreground=THEME["text_muted"]).pack(side=tk.LEFT, padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_and_render_table())
        search_entry = ttk.Entry(search_bar, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.table_count_label = ttk.Label(search_bar, text="0 items", background=THEME["bg_surface"], foreground=THEME["text_secondary"], font=FONT_REGULAR)
        self.table_count_label.pack(side=tk.RIGHT, padx=2)

        # Master Table
        grid_frame = ttk.Frame(table_container)
        grid_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("id", "type", "name", "path", "timestamp", "threat")
        self.main_table = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        
        col_headers = {
            "id": ("#", 50),
            "type": ("Artifact Type", 140),
            "name": ("Binary / Resource", 220),
            "path": ("Source Path / Target", 440),
            "timestamp": ("Timestamp (UTC)", 165),
            "threat": ("Threat Indicators", 140)
        }
        for col_id, (header_text, width) in col_headers.items():
            self.main_table.heading(col_id, text=header_text, command=lambda c=col_id: self._sort_table_column(c))
            self.main_table.column(col_id, width=width, anchor=tk.W)

        self.main_table.tag_configure("threat", background=THEME["accent_threat_bg"], foreground="#FCA5A5")
        self.main_table.tag_configure("normal", foreground=THEME["text_primary"])

        v_scroll = ttk.Scrollbar(grid_frame, orient=tk.VERTICAL, command=self.main_table.yview)
        h_scroll = ttk.Scrollbar(grid_frame, orient=tk.HORIZONTAL, command=self.main_table.xview)
        self.main_table.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.main_table.pack(fill=tk.BOTH, expand=True)
        self.main_table.bind("<<TreeviewSelect>>", self._on_artifact_select)

        # Bottom Inspector
        inspector_frame = ttk.Frame(paned, style="Elevated.TFrame")
        paned.add(inspector_frame, weight=2)

        ins_header = ttk.Frame(inspector_frame, style="Surface.TFrame", padding=(8, 4))
        ins_header.pack(fill=tk.X)
        ttk.Label(ins_header, text="DETAIL INSPECTOR", font=FONT_HEADING, foreground=THEME["accent_blue"], background=THEME["bg_surface"]).pack(side=tk.LEFT)
        self.ins_selected_title = ttk.Label(ins_header, text="[None Selected]", font=FONT_MONO, foreground=THEME["text_secondary"], background=THEME["bg_surface"])
        self.ins_selected_title.pack(side=tk.RIGHT)

        self.ins_notebook = ttk.Notebook(inspector_frame)
        self.ins_notebook.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # TAB 1: OVERVIEW
        tab_overview = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=10)
        self.ins_notebook.add(tab_overview, text="Overview")

        self.ins_lbl_type = ttk.Label(tab_overview, text="Type: -", font=FONT_BOLD, foreground="#38BDF8", background=THEME["bg_surface"])
        self.ins_lbl_type.grid(row=0, column=0, sticky=tk.W, pady=2)

        self.ins_lbl_time = ttk.Label(tab_overview, text="Timestamp (UTC): -", font=FONT_MONO_BOLD, foreground="#3FB950", background=THEME["bg_surface"])
        self.ins_lbl_time.grid(row=0, column=1, sticky=tk.W, pady=2, padx=16)

        self.ins_lbl_name = ttk.Label(tab_overview, text="Resource: -", font=FONT_BOLD, foreground="#F0F6FC", background=THEME["bg_surface"])
        self.ins_lbl_name.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=2)

        self.ins_lbl_path = ttk.Label(tab_overview, text="Path: -", font=FONT_MONO, foreground="#BC8CFF", background=THEME["bg_surface"])
        self.ins_lbl_path.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)

        ttk.Label(tab_overview, text="Decoded Extra Attributes & Parameters:", font=FONT_HEADING, foreground="#FFA657", background=THEME["bg_surface"]).grid(row=3, column=0, sticky=tk.W, pady=(8, 2))
        self.ins_txt_extra = tk.Text(tab_overview, height=3, background=THEME["bg_elevated"], foreground="#FFA657", insertbackground=THEME["accent_blue"], borderwidth=0, font=FONT_MONO, wrap=tk.WORD)
        self.ins_txt_extra.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=2)

        tab_overview.columnconfigure(0, weight=1)
        tab_overview.columnconfigure(1, weight=1)
        tab_overview.rowconfigure(4, weight=1)

        # TAB 2: THREAT CONTEXT
        tab_threat = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=10)
        self.ins_notebook.add(tab_threat, text="Threat Context")
        self.ins_txt_threat = tk.Text(tab_threat, background="#221215", foreground="#FCA5A5", insertbackground=THEME["accent_blue"], borderwidth=0, font=FONT_MONO, wrap=tk.WORD)
        self.ins_txt_threat.pack(fill=tk.BOTH, expand=True)

        # TAB 3: RAW JSON
        tab_json = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=10)
        self.ins_notebook.add(tab_json, text="Raw JSON")
        self.ins_txt_json = tk.Text(tab_json, background="#0B0E14", foreground="#58A6FF", insertbackground=THEME["accent_blue"], borderwidth=0, font=FONT_MONO, wrap=tk.NONE)
        self.ins_txt_json.pack(fill=tk.BOTH, expand=True)

    def _populate_hierarchical_category_tree(self):
        for item in self.tree_categories.get_children():
            self.tree_categories.delete(item)

        self.tree_categories.insert("", tk.END, iid="all", text="All Artifacts", open=True)
        self.tree_categories.insert("", tk.END, iid="threats", text="🚨 Threat Flags", open=True)

        self.tree_categories.insert("", tk.END, iid="sec_exec", text="Program Execution", open=True)
        self.tree_categories.insert("sec_exec", tk.END, iid="prefetch", text="Prefetch (.pf)")
        self.tree_categories.insert("sec_exec", tk.END, iid="userassist", text="UserAssist (ROT13)")
        self.tree_categories.insert("sec_exec", tk.END, iid="bam", text="BAM / DAM Kernel")
        self.tree_categories.insert("sec_exec", tk.END, iid="startup", text="Startup Autoruns")

        self.tree_categories.insert("", tk.END, iid="sec_file", text="File & Folder Access", open=True)
        self.tree_categories.insert("sec_file", tk.END, iid="lnk", text="LNK Shortcuts")
        self.tree_categories.insert("sec_file", tk.END, iid="shellbag", text="Explorer ShellBags")
        self.tree_categories.insert("sec_file", tk.END, iid="jumplist", text="Jump Lists")
        self.tree_categories.insert("sec_file", tk.END, iid="recycle", text="Recycle Bin")

        self.tree_categories.insert("", tk.END, iid="sec_web", text="Communications & Web", open=True)
        self.tree_categories.insert("sec_web", tk.END, iid="browser", text="Visited URLs")
        self.tree_categories.insert("sec_web", tk.END, iid="download", text="File Downloads")
        self.tree_categories.insert("sec_web", tk.END, iid="powershell", text="PowerShell History")

        self.tree_categories.insert("", tk.END, iid="sec_sec", text="Devices & Security", open=True)
        self.tree_categories.insert("sec_sec", tk.END, iid="usb", text="USB Devices")
        self.tree_categories.insert("sec_sec", tk.END, iid="event", text="Security Event Logs")

        self.tree_categories.selection_set("all")

    def _on_category_select(self, event):
        sel = self.tree_categories.selection()
        if sel:
            self.active_category = sel[0]
            self.filter_and_render_table()

    # -------------------------------------------------------------
    # BUILD TAB 3: VISUAL ANALYTICS (Matplotlib Dashboard)
    # -------------------------------------------------------------
    def _build_analytics_tab(self, parent):
        top_ctrl = ttk.Frame(parent, style="Elevated.TFrame", padding=(10, 6))
        top_ctrl.pack(fill=tk.X)

        ttk.Label(top_ctrl, text="EVIDENCE METRICS & CHARTS", font=FONT_HEADING, foreground=THEME["accent_blue"], background=THEME["bg_elevated"]).pack(side=tk.LEFT)
        ttk.Button(top_ctrl, text="Refresh Charts", command=self._render_analytics_charts).pack(side=tk.RIGHT, padx=2)

        self.analytics_canvas_frame = ttk.Frame(parent, style="Surface.TFrame")
        self.analytics_canvas_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.fig = plt.Figure(figsize=(11, 7), facecolor=THEME["bg_surface"])
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.analytics_canvas_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _render_analytics_charts(self):
        self.fig.clear()
        
        # 1. Timeline Histogram (Sapphire Blue with non-overlapping spaced dates)
        ax1 = self.fig.add_subplot(2, 2, (1, 2))
        ax1.set_facecolor(THEME["bg_elevated"])
        time_buckets = {}
        for art in self.all_artifacts:
            t = art.get("timestamp") or art.get("last_access")
            if t and len(t) >= 10:
                day = t[:10]
                time_buckets[day] = time_buckets.get(day, 0) + 1

        sorted_days = sorted(time_buckets.keys())
        day_counts = [time_buckets[d] for d in sorted_days]
        if sorted_days:
            x_indices = list(range(len(sorted_days)))
            ax1.bar(x_indices, day_counts, color=THEME["accent_blue"], edgecolor="#1F6FEB", alpha=0.85)
            ax1.set_title("Chronological Activity Density (Events over Time)", color=THEME["text_primary"], fontsize=10, fontweight="bold")
            
            # Sample at most 6-8 evenly spaced ticks to eliminate cluttered overlapping text below graph
            num_days = len(sorted_days)
            if num_days > 7:
                step = max(1, num_days // 6)
                tick_pos = list(range(0, num_days, step))
                if (num_days - 1) not in tick_pos:
                    tick_pos.append(num_days - 1)
                ax1.set_xticks(tick_pos)
                ax1.set_xticklabels([sorted_days[i] for i in tick_pos], rotation=0, fontsize=8, color=THEME["text_secondary"])
            else:
                ax1.set_xticks(x_indices)
                ax1.set_xticklabels(sorted_days, rotation=0, fontsize=8, color=THEME["text_secondary"])

            ax1.tick_params(colors=THEME["text_secondary"], labelsize=8)
            ax1.grid(axis="y", linestyle="--", alpha=0.15)
        else:
            ax1.text(0.5, 0.5, "No Timestamped Evidence Available", color=THEME["text_muted"], ha="center", va="center", fontsize=9)

        # 2. Category Donut (Vibrant Palette)
        ax2 = self.fig.add_subplot(2, 2, 3)
        ax2.set_facecolor(THEME["bg_surface"])
        cat_counts = {}
        for art in self.all_artifacts:
            t = art.get("artifact_type") or "Unknown"
            cat_counts[t] = cat_counts.get(t, 0) + 1

        top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        if top_cats:
            donut_colors = [THEME["accent_blue"], THEME["accent_green"], THEME["accent_purple"], "#FFA657", "#39C5CF", THEME["accent_amber"]]
            ax2.pie([c[1] for c in top_cats], labels=[c[0] for c in top_cats], textprops={"color": THEME["text_secondary"], "fontsize": 8},
                    colors=donut_colors[:len(top_cats)], wedgeprops={"edgecolor": THEME["bg_surface"], "width": 0.5})
            ax2.set_title("Evidence Categories", color=THEME["text_primary"], fontsize=10, fontweight="bold")
        else:
            ax2.text(0.5, 0.5, "No Categories", color=THEME["text_muted"], ha="center", va="center", fontsize=9)

        # 3. Top Apps Bar (Emerald Green)
        ax3 = self.fig.add_subplot(2, 2, 4)
        ax3.set_facecolor(THEME["bg_elevated"])
        app_counts = {}
        for art in self.all_artifacts:
            t = (art.get("artifact_type") or "").lower()
            if "prefetch" in t or "userassist" in t or "bam" in t:
                name = (art.get("name") or "Unknown").replace("\\", "/").split("/")[-1]
                if "-" in name and name.upper().endswith(".PF"):
                    name = name.split("-")[0]
                app_counts[name] = app_counts.get(name, 0) + 1

        top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_apps:
            ax3.barh([a[0] for a in top_apps][::-1], [a[1] for a in top_apps][::-1], color=THEME["accent_green"], edgecolor="#238636", alpha=0.85)
            ax3.set_title("Top Executed Applications", color=THEME["text_primary"], fontsize=10, fontweight="bold")
            ax3.tick_params(colors=THEME["text_secondary"], labelsize=8)
            ax3.grid(axis="x", linestyle="--", alpha=0.15)
        else:
            ax3.text(0.5, 0.5, "No Execution Records", color=THEME["text_muted"], ha="center", va="center", fontsize=9)

        self.fig.tight_layout(pad=2.0)
        self.canvas.draw()

    # -------------------------------------------------------------
    # BUILD TAB 4: ARTIFACT CATALOG
    # -------------------------------------------------------------
    def _build_catalog_tab(self, parent):
        intro_frame = ttk.Frame(parent, style="Elevated.TFrame", padding=10)
        intro_frame.pack(fill=tk.X, padx=6, pady=4)
        ttk.Label(intro_frame, text="Windows Forensic Artifact Catalog", font=FONT_HEADING, foreground=THEME["accent_blue"], background=THEME["bg_elevated"]).pack(anchor=tk.W)
        ttk.Label(intro_frame, text="Double-click any row to load its path into the Target Scanner.", font=FONT_REGULAR, foreground=THEME["text_secondary"], background=THEME["bg_elevated"]).pack(anchor=tk.W)

        cols = ("id", "name", "category", "path", "description")
        self.cat_tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        
        headers = {
            "id": ("ID", 100),
            "name": ("Artifact Name", 150),
            "category": ("Category", 130),
            "path": ("Default Live Location / Key", 380),
            "description": ("Forensic Value", 420)
        }
        for k, (txt, w) in headers.items():
            self.cat_tree.heading(k, text=txt)
            self.cat_tree.column(k, width=w)

        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.cat_tree.yview)
        self.cat_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.cat_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.cat_tree.bind("<Double-1>", self._on_catalog_double_click)

        catalog = path_resolver.get_catalog()
        for it in catalog:
            lp = it.get("live_paths", ["Auto-detected"])[0]
            self.cat_tree.insert("", tk.END, values=(
                it.get("id"),
                it.get("name"),
                it.get("category"),
                lp,
                it.get("description")
            ))

    def _on_catalog_double_click(self, event):
        sel = self.cat_tree.selection()
        if not sel: return
        vals = self.cat_tree.item(sel[0], "values")
        if vals and len(vals) >= 4:
            path_val = vals[3]
            if not path_val.startswith("REGISTRY:"):
                self.target_path_var.set(path_val)
                messagebox.showinfo("Path Loaded", f"Loaded path for '{vals[1]}'. Click 'Scan Target' to extract.")

    # -------------------------------------------------------------
    # DATA REFRESH & FILTERS
    # -------------------------------------------------------------
    def refresh_evidence_data(self):
        self.status_indicator.config(text="● Querying DB...", foreground=THEME["text_muted"])
        self.all_artifacts = [dict(r) for r in query_artifacts(DB_PATH)]
        self.all_correlations = core_logic.get_correlations_json()
        stats = core_logic.get_stats_core()
        
        self.sidebar_total_badge.config(text=f"{len(self.all_artifacts):,}")
        sha = stats.get("db_sha256", "N/A")
        self.db_sha_label.config(text=f"DB SHA: {sha[:12]}..." if len(sha) > 12 else f"DB SHA: {sha}")
        self.status_indicator.config(text=f"● Indexed {len(self.all_artifacts):,} items ({stats.get('anomalies_detected', 0)} threats)", foreground=THEME["accent_green"])
        
        self.filter_and_render_table()
        self._filter_timeline_table()
        self._render_analytics_charts()

    def filter_and_render_table(self):
        q = self.search_var.get().strip().lower()
        self.filtered_artifacts = []

        for art in self.all_artifacts:
            t = (art.get("artifact_type") or "").lower()
            extra = (art.get("extra") or "").lower()

            if self.active_category == "threats":
                if not (("threat_tag" in extra) or ("critical" in extra) or ("tampering" in extra) or ("1102" in extra)):
                    continue
            elif self.active_category == "sec_exec" and not ("prefetch" in t or "userassist" in t or "bam" in t or "startup" in t): continue
            elif self.active_category == "sec_file" and not ("lnk" in t or "shellbag" in t or "jumplist" in t or "recycle" in t): continue
            elif self.active_category == "sec_web" and not ("browser" in t or "download" in t or "powershell" in t): continue
            elif self.active_category == "sec_sec" and not ("usb" in t or "event" in t or "logon" in t): continue
            elif self.active_category == "prefetch" and "prefetch" not in t: continue
            elif self.active_category == "userassist" and "userassist" not in t: continue
            elif self.active_category == "bam" and "bam" not in t: continue
            elif self.active_category == "startup" and "startup" not in t: continue
            elif self.active_category == "lnk" and "lnk" not in t: continue
            elif self.active_category == "shellbag" and "shellbag" not in t: continue
            elif self.active_category == "jumplist" and "jumplist" not in t: continue
            elif self.active_category == "recycle" and "recycle" not in t: continue
            elif self.active_category == "browser" and "browser_url" not in t: continue
            elif self.active_category == "download" and "browser_download" not in t: continue
            elif self.active_category == "powershell" and "powershell" not in t: continue
            elif self.active_category == "usb" and "usb" not in t: continue
            elif self.active_category == "event" and not ("event" in t or "logon" in t): continue

            if q:
                match_blob = f"{art.get('name', '')} {art.get('path', '')} {art.get('artifact_type', '')} {art.get('extra', '')} {art.get('timestamp', '')}".lower()
                if q not in match_blob:
                    continue

            self.filtered_artifacts.append(art)

        def sort_key(x):
            val = x.get(self.sort_column) or ""
            return str(val).lower()

        self.filtered_artifacts.sort(key=sort_key, reverse=not self.sort_ascending)

        for r in self.main_table.get_children():
            self.main_table.delete(r)

        self.table_count_label.config(text=f"Showing {len(self.filtered_artifacts):,} of {len(self.all_artifacts):,}")

        for art in self.filtered_artifacts[:1000]:
            extra_str = art.get("extra") or ""
            is_threat = ("threat_tag" in extra_str.lower()) or ("critical" in extra_str.lower()) or ("tampering" in extra_str.lower()) or ("1102" in extra_str)
            threat_txt = "🚨 Threat Flag" if is_threat else "Normal"
            tag = "threat" if is_threat else "normal"

            self.main_table.insert("", tk.END, iid=str(art.get("id")), values=(
                art.get("id"),
                art.get("artifact_type"),
                art.get("name") or "Unnamed",
                art.get("path") or "-",
                art.get("timestamp") or art.get("last_access") or "-",
                threat_txt
            ), tags=(tag,))

    def _sort_table_column(self, col):
        if self.sort_column == col:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = col
            self.sort_ascending = True
        self.filter_and_render_table()

    def _on_artifact_select(self, event):
        sel = self.main_table.selection()
        if not sel: return
        art_id = int(sel[0])
        target = next((a for a in self.all_artifacts if a.get("id") == art_id), None)
        if not target: return

        self.ins_selected_title.config(text=f"[ID {target.get('id')}] {target.get('name') or target.get('artifact_type')}")
        self.ins_lbl_type.config(text=f"Type: {target.get('artifact_type', 'Unknown')}")
        self.ins_lbl_time.config(text=f"Timestamp: {target.get('timestamp') or target.get('last_access') or 'N/A'}")
        self.ins_lbl_name.config(text=f"Resource: {target.get('name') or 'N/A'}")
        self.ins_lbl_path.config(text=f"Path: {target.get('path') or 'N/A'}")

        self.ins_txt_extra.delete("1.0", tk.END)
        self.ins_txt_extra.insert(tk.END, target.get("extra") or "None")

        self.ins_txt_threat.delete("1.0", tk.END)
        extra_str = target.get("extra") or ""
        if "threat_tag" in extra_str.lower() or "critical" in extra_str.lower() or "tampering" in extra_str.lower():
            self.ins_txt_threat.insert(tk.END, f"🚨 THREAT DETECTION TRIGGERED:\n\n{extra_str}")
        else:
            self.ins_txt_threat.insert(tk.END, "No anomaly flags triggered for this item.")

        self.ins_txt_json.delete("1.0", tk.END)
        try:
            details = target.get("details")
            raw_data = json.loads(details) if isinstance(details, str) else (details or target)
            self.ins_txt_json.insert(tk.END, json.dumps(raw_data, indent=2))
        except Exception:
            self.ins_txt_json.insert(tk.END, json.dumps(target, indent=2))

    # -------------------------------------------------------------
    # FORENSIC ACTIONS
    # -------------------------------------------------------------
    def action_live_triage(self):
        self.status_indicator.config(text="● Triage running...", foreground=THEME["accent_blue"])
        threading.Thread(target=self._live_triage_worker, daemon=True).start()

    def _live_triage_worker(self):
        res = core_logic.parse_live_triage_core()
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Triage Complete", res.get("message", "Finished.")))

    def action_run_preset(self):
        idx = self.preset_combo.current()
        preset_map = {
            0: "all_triage",
            1: "execution_persistence",
            2: "file_access",
            3: "browser_downloads",
            4: "powershell_cli",
            5: "usb_storage",
            6: "event_logs"
        }
        pid = preset_map.get(idx, "all_triage")
        self.status_indicator.config(text=f"● Processing '{pid}'...", foreground=THEME["accent_blue"])
        threading.Thread(target=lambda: self._preset_worker(pid), daemon=True).start()

    def _preset_worker(self, pid):
        res = core_logic.parse_preset_core(pid)
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Preset Complete", res.get("message", "Done.")))

    def action_browse_target(self):
        d = filedialog.askdirectory(title="Select Target Folder or Drive")
        if d:
            self.target_path_var.set(d)

    def action_scan_target(self):
        p = self.target_path_var.get().strip()
        if not p or not os.path.isdir(p):
            messagebox.showerror("Invalid Path", "Please enter a valid directory path.")
            return
        self.status_indicator.config(text=f"● Scanning '{p}'...", foreground=THEME["accent_blue"])
        threading.Thread(target=lambda: self._target_worker(p), daemon=True).start()

    def _target_worker(self, p):
        res = core_logic.parse_target_folder_core(p)
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Scan Finished", res.get("message", "Done.")))

    def action_clear_db(self):
        if messagebox.askyesno("Confirm Clear", "Erase all indexed forensic artifacts from the database?"):
            core_logic.clear_database_core()
            self.refresh_evidence_data()
            messagebox.showinfo("Database Cleared", "Database cleared successfully.")

    def action_export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Export CSV")
        if p:
            res = core_logic.generate_csv_report(p)
            messagebox.showinfo("Exported", res.get("message", "Done."))

    def action_export_json(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], title="Export JSON")
        if p:
            res = core_logic.export_json_report(p)
            messagebox.showinfo("Exported", res.get("message", "Done."))

    def action_export_pdf(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Export Forensic Audit PDF")
        if p:
            meta = {
                "caseNumber": "CASE-2026-DESKTOP",
                "evidenceNumber": "EVID-001-WIN-HOST",
                "examiner": os.environ.get("USERNAME", "Examiner"),
                "uniqueDescription": "Windows User Activity & Timeline Reconstruction",
                "notes": "Generated via Footprint Analyzer."
            }
            res = core_logic.generate_pdf_report_core(p, meta)
            if res.get("status") == "success":
                messagebox.showinfo("PDF Generated", res.get("message", "Done."))
            else:
                messagebox.showerror("PDF Error", res.get("message", "Error."))

    def action_export_corr_pdf(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Export Correlation Timeline PDF")
        if p:
            meta = {
                "caseNumber": "CORR-2026-TIMELINE",
                "evidenceNumber": "EVID-001-CORRELATED",
                "examiner": os.environ.get("USERNAME", "Examiner"),
                "uniqueDescription": "Reconstructed Cross-Artifact Timeline",
                "notes": "Generated via Windows User Activity Reconstruction Correlator."
            }
            res = core_logic.generate_correlation_pdf_core(p, meta)
            if res.get("status") == "success":
                messagebox.showinfo("Correlation PDF Generated", res.get("message", "Done."))
            else:
                messagebox.showerror("PDF Error", res.get("message", "Error."))

if __name__ == "__main__":
    app = WinActivityReconApp()
    app.mainloop()
