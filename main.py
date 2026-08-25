# main.py
"""
AegisDFIR - Windows Forensic Artifacts Parser & User Activity Reconstruction Desktop GUI.
Enterprise-grade multi-pane native forensic workstation (Autopsy / Magnet AXIOM style)
featuring 1-Click Live Triage, Auto-Discovery Scanners, Real-Time Evidence Inspector,
Embedded Visual Analytics (Matplotlib), Prominent Clear Controls, and High-Readability Typography.
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
TOOL_VERSION = "v1.3.1"

# High-Readability Cyber Forensics Theme (Slate & Deep Navy)
THEME = {
    "bg_base": "#0F172A",        # Rich Slate Navy
    "bg_surface": "#1E293B",     # Elevated Card Panel
    "bg_elevated": "#334155",    # Active Control Background
    "bg_highlight": "#475569",   # Hover / Highlight
    "bg_selected": "#0284C7",    # Vibrant Blue Selection
    "text_primary": "#F8FAFC",   # 100% Crisp White Text
    "text_secondary": "#CBD5E1", # High-contrast Light Slate
    "text_muted": "#94A3B8",     # Clear Muted Gray
    "cyan_accent": "#38BDF8",    # Sky Cyan Accent
    "blue_accent": "#60A5FA",    # Royal Blue Accent
    "green_accent": "#10B981",   # Emerald Green
    "red_accent": "#EF4444",     # Crimson Alert Red
    "purple_accent": "#C084FC",  # Purple Accent
    "border": "#334155",
}

FONT_TITLE = ("Segoe UI", 13, "bold")
FONT_HEADING = ("Segoe UI", 10, "bold")
FONT_REGULAR = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")

class AegisDFIRDesktopApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AegisDFIR - Windows Forensic Analysis Workstation (v1.3.1)")
        self.geometry("1380x860")
        self.minsize(1100, 700)
        
        # State
        self.all_artifacts: List[Dict[str, Any]] = []
        self.filtered_artifacts: List[Dict[str, Any]] = []
        self.active_category: str = "all"
        self.sort_column: str = "id"
        self.sort_ascending: bool = False
        
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

        # Base Config
        style.configure(".", background=THEME["bg_base"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("TFrame", background=THEME["bg_base"])
        style.configure("Surface.TFrame", background=THEME["bg_surface"])
        style.configure("Elevated.TFrame", background=THEME["bg_elevated"])
        style.configure("TLabel", background=THEME["bg_base"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("Surface.TLabel", background=THEME["bg_surface"], foreground=THEME["text_primary"], font=FONT_REGULAR)
        style.configure("Muted.TLabel", background=THEME["bg_surface"], foreground=THEME["text_muted"], font=FONT_SMALL)
        style.configure("Header.TLabel", font=FONT_TITLE, foreground=THEME["cyan_accent"], background=THEME["bg_surface"])

        # Buttons
        style.configure("TButton", background=THEME["bg_elevated"], foreground=THEME["text_primary"], borderwidth=1, bordercolor=THEME["border"], padding=(10, 6), font=FONT_BOLD)
        style.map("TButton", background=[("active", THEME["bg_highlight"]), ("hover", THEME["bg_highlight"])], foreground=[("active", THEME["cyan_accent"])])

        style.configure("Primary.TButton", background=THEME["cyan_accent"], foreground="#000000", font=FONT_BOLD, borderwidth=0, padding=(12, 6))
        style.map("Primary.TButton", background=[("active", "#0284C7"), ("hover", "#0284C7")], foreground=[("active", "#FFFFFF"), ("hover", "#FFFFFF")])

        style.configure("Export.TButton", background=THEME["green_accent"], foreground="#FFFFFF", font=FONT_BOLD, borderwidth=0, padding=(12, 6))
        style.map("Export.TButton", background=[("active", "#059669"), ("hover", "#059669")])

        style.configure("Danger.TButton", background=THEME["red_accent"], foreground="#FFFFFF", font=FONT_BOLD, borderwidth=0, padding=(12, 6))
        style.map("Danger.TButton", background=[("active", "#DC2626"), ("hover", "#DC2626")])

        # Inputs & Comboboxes
        style.configure("TEntry", fieldbackground=THEME["bg_surface"], foreground=THEME["text_primary"], insertcolor=THEME["cyan_accent"], bordercolor=THEME["border"], padding=6, font=FONT_REGULAR)
        style.configure("TCombobox", fieldbackground=THEME["bg_surface"], foreground=THEME["text_primary"], selectbackground=THEME["bg_highlight"], selectforeground=THEME["text_primary"], bordercolor=THEME["border"], font=FONT_REGULAR)
        style.map("TCombobox", fieldbackground=[("readonly", THEME["bg_surface"])], foreground=[("readonly", THEME["text_primary"])])

        # Treeview / Data Grid (Increased rowheight for spacious readability)
        style.configure("Treeview", background=THEME["bg_surface"], fieldbackground=THEME["bg_surface"], foreground=THEME["text_primary"], rowheight=32, borderwidth=0, font=FONT_REGULAR)
        style.map("Treeview", background=[("selected", THEME["bg_selected"])], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview.Heading", background=THEME["bg_elevated"], foreground=THEME["cyan_accent"], font=FONT_HEADING, bordercolor=THEME["border"], padding=6)
        style.map("Treeview.Heading", background=[("active", THEME["bg_highlight"])], foreground=[("active", THEME["cyan_accent"])])

        # Notebook Tabs
        style.configure("TNotebook", background=THEME["bg_surface"], borderwidth=0)
        style.configure("TNotebook.Tab", background=THEME["bg_elevated"], foreground=THEME["text_secondary"], padding=(14, 6), font=FONT_HEADING)
        style.map("TNotebook.Tab", background=[("selected", THEME["bg_surface"])], foreground=[("selected", THEME["cyan_accent"])])

    def _build_menu(self):
        menubar = tk.Menu(self, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["cyan_accent"], font=FONT_REGULAR)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["cyan_accent"])
        file_menu.add_command(label="⚡ 1-Click Live Triage", command=self.action_live_triage)
        file_menu.add_command(label="🔍 Auto-Scan Target Folder...", command=self.action_browse_target)
        file_menu.add_separator()
        file_menu.add_command(label="🔄 Refresh Dataset", command=self.refresh_evidence_data, accelerator="F5")
        file_menu.add_command(label="🗑️ Clear Evidence Database", command=self.action_clear_db, accelerator="Ctrl+Del")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        # Export Menu
        export_menu = tk.Menu(menubar, tearoff=0, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["cyan_accent"])
        export_menu.add_command(label="📑 Export Executive PDF Audit Report...", command=self.action_export_pdf)
        export_menu.add_command(label="📄 Export Standard CSV Timeline...", command=self.action_export_csv)
        export_menu.add_command(label="📦 Export DFIR JSON Timeline...", command=self.action_export_json)
        menubar.add_cascade(label="Export", menu=export_menu)

        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0, background=THEME["bg_surface"], foreground=THEME["text_primary"], activebackground=THEME["bg_highlight"], activeforeground=THEME["cyan_accent"])
        tools_menu.add_command(label="📊 Open Visual Analytics Dashboard", command=self.open_visual_analytics_modal)
        tools_menu.add_command(label="⏱️ Open Reconstructed Session Timeline", command=self.open_timeline_window)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        self.config(menu=menubar)
        self.bind("<F5>", lambda e: self.refresh_evidence_data())
        self.bind("<Control-Delete>", lambda e: self.action_clear_db())

    def _build_ui(self):
        # Master Container
        master_frame = ttk.Frame(self)
        master_frame.pack(fill=tk.BOTH, expand=True)

        # 1. TOP HEADER & TELEMETRY BAR (Spacious)
        header = ttk.Frame(master_frame, style="Surface.TFrame", padding=(18, 12))
        header.pack(fill=tk.X)

        hdr_left = ttk.Frame(header, style="Surface.TFrame")
        hdr_left.pack(side=tk.LEFT)
        ttk.Label(hdr_left, text="🛡️ AEGIS-DFIR WORKSTATION", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr_left, text=" | Windows Forensic & Activity Reconstruction", font=FONT_BOLD, foreground=THEME["text_secondary"], background=THEME["bg_surface"]).pack(side=tk.LEFT, padx=6)
        ttk.Label(hdr_left, text="v1.3.1", font=FONT_SMALL, foreground=THEME["text_muted"], background=THEME["bg_elevated"], padding=(4, 2)).pack(side=tk.LEFT, padx=6)

        hdr_right = ttk.Frame(header, style="Surface.TFrame")
        hdr_right.pack(side=tk.RIGHT)
        self.status_indicator = ttk.Label(hdr_right, text="● Host Analysis Ready", font=FONT_BOLD, foreground=THEME["green_accent"], background=THEME["bg_surface"])
        self.status_indicator.pack(side=tk.LEFT, padx=10)

        self.db_sha_label = ttk.Label(hdr_right, text="DB SHA-256: Acquiring...", font=FONT_MONO, foreground=THEME["cyan_accent"], background=THEME["bg_elevated"], padding=(8, 3))
        self.db_sha_label.pack(side=tk.LEFT, padx=6)

        # 2. ACQUISITION COMMAND BAR (Spacious & Prominent)
        acq_bar = ttk.Frame(master_frame, style="Elevated.TFrame", padding=(12, 10))
        acq_bar.pack(fill=tk.X, padx=8, pady=(4, 2))

        # 1-Click Live Triage
        ttk.Button(acq_bar, text="⚡ 1-Click Live Triage", style="Primary.TButton", command=self.action_live_triage).pack(side=tk.LEFT, padx=(0, 8))

        # Preset Dropdown
        ttk.Label(acq_bar, text="Category Preset:", background=THEME["bg_elevated"], foreground=THEME["text_secondary"], font=FONT_BOLD).pack(side=tk.LEFT, padx=(6, 4))
        self.preset_var = tk.StringVar()
        self.preset_combo = ttk.Combobox(acq_bar, textvariable=self.preset_var, width=32, state="readonly", font=FONT_REGULAR)
        self.preset_combo["values"] = [
            "⚡ Full Live Triage (All 12 Artifacts)",
            "🚀 Program Execution & Persistence",
            "📁 File & Folder Knowledge",
            "🌐 Web Browsers & Downloads",
            "💻 PowerShell CLI History",
            "🔌 USB Storage Devices",
            "🛡️ Security & Windows Event Logs"
        ]
        self.preset_combo.current(0)
        self.preset_combo.pack(side=tk.LEFT, padx=4)
        ttk.Button(acq_bar, text="Run Preset", command=self.action_run_preset).pack(side=tk.LEFT, padx=(0, 14))

        # Target Auto-Scanner
        self.target_path_var = tk.StringVar()
        target_entry = ttk.Entry(acq_bar, textvariable=self.target_path_var, width=28)
        target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(4, 4))
        ttk.Button(acq_bar, text="Browse...", command=self.action_browse_target).pack(side=tk.LEFT, padx=2)
        ttk.Button(acq_bar, text="🔍 Auto-Scan Target", command=self.action_scan_target).pack(side=tk.LEFT, padx=(0, 14))

        # RIGHT ACTIONS BAR: PROMINENT CLEAR DB, ANALYTICS, EXPORTS
        # Prominent CLEAR DATABASE Button (Highly visible Red Button)
        ttk.Button(acq_bar, text="🗑️ Clear Database", style="Danger.TButton", command=self.action_clear_db).pack(side=tk.RIGHT, padx=4)
        ttk.Button(acq_bar, text="📑 PDF Report", style="Export.TButton", command=self.action_export_pdf).pack(side=tk.RIGHT, padx=4)
        ttk.Button(acq_bar, text="📊 Visual Analytics", style="Primary.TButton", command=self.open_visual_analytics_modal).pack(side=tk.RIGHT, padx=4)
        ttk.Button(acq_bar, text="⏱️ Timeline", command=self.open_timeline_window).pack(side=tk.RIGHT, padx=4)
        ttk.Button(acq_bar, text="🔄 Refresh", command=self.refresh_evidence_data).pack(side=tk.RIGHT, padx=4)

        # 3. MAIN WORKSPACE (SPLIT: SIDEBAR TREE + DATA GRID + DOCKED INSPECTOR)
        workspace = ttk.Frame(master_frame)
        workspace.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # LEFT SIDEBAR: EVIDENCE CATEGORY TREE (Spacious with high readability)
        sidebar_frame = ttk.Frame(workspace, style="Surface.TFrame", width=250)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        sidebar_frame.pack_propagate(False)

        sb_header = ttk.Frame(sidebar_frame, style="Elevated.TFrame", padding=(10, 8))
        sb_header.pack(fill=tk.X)
        ttk.Label(sb_header, text="EVIDENCE TREE", font=FONT_HEADING, foreground=THEME["cyan_accent"], background=THEME["bg_elevated"]).pack(side=tk.LEFT)
        self.sidebar_total_badge = ttk.Label(sb_header, text="0", font=FONT_MONO_BOLD, foreground="#FFFFFF", background=THEME["bg_selected"], padding=(6, 2))
        self.sidebar_total_badge.pack(side=tk.RIGHT)

        self.tree_categories = ttk.Treeview(sidebar_frame, show="tree", selectmode="browse")
        self.tree_categories.pack(fill=tk.BOTH, expand=True, padx=4, pady=6)
        self.tree_categories.bind("<<TreeviewSelect>>", self._on_category_select)
        self._populate_category_tree()

        # RIGHT MAIN PANE (VERTICAL PANED WINDOW: TABLE ON TOP, DOCKED INSPECTOR BELOW)
        paned = ttk.PanedWindow(workspace, orient=tk.VERTICAL)
        paned.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # TOP PANE: SEARCH TOOLBAR + MASTER TABLE
        table_container = ttk.Frame(paned, style="Surface.TFrame")
        paned.add(table_container, weight=3)

        # Search & Filter Bar
        search_bar = ttk.Frame(table_container, style="Surface.TFrame", padding=(8, 6))
        search_bar.pack(fill=tk.X)

        ttk.Label(search_bar, text="🔎 Instant Search:", background=THEME["bg_surface"], font=FONT_HEADING).pack(side=tk.LEFT, padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self.filter_and_render_table())
        search_entry = ttk.Entry(search_bar, textvariable=self.search_var, width=48)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.table_count_label = ttk.Label(search_bar, text="Showing 0 of 0", background=THEME["bg_surface"], foreground=THEME["text_secondary"], font=FONT_BOLD)
        self.table_count_label.pack(side=tk.RIGHT, padx=4)

        # Master Table
        grid_frame = ttk.Frame(table_container)
        grid_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("id", "type", "name", "path", "timestamp", "threat")
        self.main_table = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        
        col_headers = {
            "id": ("#", 55),
            "type": ("Artifact Type", 150),
            "name": ("Binary / Resource", 240),
            "path": ("Source Path / Target / Command", 420),
            "timestamp": ("Timestamp (UTC)", 175),
            "threat": ("Threat Indicators", 160)
        }
        for col_id, (header_text, width) in col_headers.items():
            self.main_table.heading(col_id, text=header_text, command=lambda c=col_id: self._sort_table_column(c))
            self.main_table.column(col_id, width=width, anchor=tk.W)

        self.main_table.tag_configure("threat", background="#451A1A", foreground="#FCA5A5")
        self.main_table.tag_configure("normal", foreground=THEME["text_primary"])

        v_scroll = ttk.Scrollbar(grid_frame, orient=tk.VERTICAL, command=self.main_table.yview)
        h_scroll = ttk.Scrollbar(grid_frame, orient=tk.HORIZONTAL, command=self.main_table.xview)
        self.main_table.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.main_table.pack(fill=tk.BOTH, expand=True)
        self.main_table.bind("<<TreeviewSelect>>", self._on_artifact_select)

        # BOTTOM PANE: DOCKED EVIDENCE DETAIL INSPECTOR (Spacious Master-Detail)
        inspector_frame = ttk.Frame(paned, style="Elevated.TFrame")
        paned.add(inspector_frame, weight=2)

        ins_header = ttk.Frame(inspector_frame, style="Surface.TFrame", padding=(10, 6))
        ins_header.pack(fill=tk.X)
        ttk.Label(ins_header, text="EVIDENCE DETAIL INSPECTOR", font=FONT_HEADING, foreground=THEME["cyan_accent"], background=THEME["bg_surface"]).pack(side=tk.LEFT)
        self.ins_selected_title = ttk.Label(ins_header, text="[No Item Selected]", font=FONT_REGULAR, foreground=THEME["text_muted"], background=THEME["bg_surface"])
        self.ins_selected_title.pack(side=tk.RIGHT)

        # Inspector Tabs
        self.ins_notebook = ttk.Notebook(inspector_frame)
        self.ins_notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # TAB 1: OVERVIEW METADATA
        tab_overview = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=12)
        self.ins_notebook.add(tab_overview, text="🏷️ Forensic Overview")

        self.ins_lbl_type = ttk.Label(tab_overview, text="Artifact Type: -", font=FONT_BOLD, foreground=THEME["cyan_accent"], background=THEME["bg_surface"])
        self.ins_lbl_type.grid(row=0, column=0, sticky=tk.W, pady=3)

        self.ins_lbl_time = ttk.Label(tab_overview, text="Timestamp (UTC): -", font=FONT_MONO_BOLD, foreground=THEME["blue_accent"], background=THEME["bg_surface"])
        self.ins_lbl_time.grid(row=0, column=1, sticky=tk.W, pady=3, padx=20)

        self.ins_lbl_name = ttk.Label(tab_overview, text="Resource Name: -", font=FONT_BOLD, background=THEME["bg_surface"])
        self.ins_lbl_name.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=3)

        self.ins_lbl_path = ttk.Label(tab_overview, text="Full Path: -", font=FONT_MONO, foreground=THEME["text_secondary"], background=THEME["bg_surface"])
        self.ins_lbl_path.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=3)

        ttk.Label(tab_overview, text="Decoded Extra Attributes & Parameters:", font=FONT_HEADING, foreground=THEME["text_muted"], background=THEME["bg_surface"]).grid(row=3, column=0, sticky=tk.W, pady=(10, 3))
        self.ins_txt_extra = tk.Text(tab_overview, height=4, background=THEME["bg_elevated"], foreground=THEME["text_primary"], insertbackground=THEME["cyan_accent"], borderwidth=0, font=FONT_MONO, wrap=tk.WORD)
        self.ins_txt_extra.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=3)

        tab_overview.columnconfigure(0, weight=1)
        tab_overview.columnconfigure(1, weight=1)
        tab_overview.rowconfigure(4, weight=1)

        # TAB 2: THREAT & MITRE CONTEXT
        tab_threat = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=12)
        self.ins_notebook.add(tab_threat, text="🛡️ Threat & MITRE ATT&CK Context")
        self.ins_txt_threat = tk.Text(tab_threat, background=THEME["bg_elevated"], foreground=THEME["red_accent"], insertbackground=THEME["cyan_accent"], borderwidth=0, font=FONT_MONO, wrap=tk.WORD)
        self.ins_txt_threat.pack(fill=tk.BOTH, expand=True)

        # TAB 3: RAW JSON
        tab_json = ttk.Frame(self.ins_notebook, style="Surface.TFrame", padding=12)
        self.ins_notebook.add(tab_json, text="💻 Raw Forensic JSON")
        self.ins_txt_json = tk.Text(tab_json, background="#07090E", foreground=THEME["blue_accent"], insertbackground=THEME["cyan_accent"], borderwidth=0, font=FONT_MONO, wrap=tk.NONE)
        self.ins_txt_json.pack(fill=tk.BOTH, expand=True)

    def _populate_category_tree(self):
        for item in self.tree_categories.get_children():
            self.tree_categories.delete(item)

        self.cat_map = [
            ("all", "📦 All Evidence Items"),
            ("threats", "🚨 Threat & Anomaly Flags"),
            ("prefetch", "🚀 Prefetch (.pf)"),
            ("userassist", "👤 UserAssist (ROT13)"),
            ("bam", "⚙️ BAM / DAM Kernel"),
            ("startup", "🔄 Startup & Persistence"),
            ("lnk", "🔗 LNK Shortcuts"),
            ("shellbag", "📂 Explorer ShellBags"),
            ("jumplist", "📋 Jump Lists"),
            ("recycle", "🗑️ Recycle Bin ($I/$R)"),
            ("browser", "🌐 Web URLs & History"),
            ("download", "📥 Browser Downloads"),
            ("powershell", "💻 PowerShell History"),
            ("usb", "🔌 USB & Storage Devices"),
            ("event", "🛡️ Security Event Logs")
        ]
        for cat_id, cat_name in self.cat_map:
            self.tree_categories.insert("", tk.END, iid=cat_id, text=cat_name)

        self.tree_categories.selection_set("all")

    def _on_category_select(self, event):
        sel = self.tree_categories.selection()
        if sel:
            self.active_category = sel[0]
            self.filter_and_render_table()

    def refresh_evidence_data(self):
        self.status_indicator.config(text="● Querying Evidence DB...", foreground=THEME["cyan_accent"])
        self.all_artifacts = [dict(r) for r in query_artifacts(DB_PATH)]
        stats = core_logic.get_stats_core()
        
        self.sidebar_total_badge.config(text=f"{len(self.all_artifacts):,}")
        sha = stats.get("db_sha256", "N/A")
        self.db_sha_label.config(text=f"DB SHA-256: {sha[:16]}..." if len(sha) > 16 else f"DB SHA-256: {sha}")
        self.status_indicator.config(text=f"● Indexed {len(self.all_artifacts):,} Items ({stats.get('anomalies_detected', 0)} Flags)", foreground=THEME["green_accent"])
        self.filter_and_render_table()

    def filter_and_render_table(self):
        q = self.search_var.get().strip().lower()
        self.filtered_artifacts = []

        for art in self.all_artifacts:
            # 1. Category Filter
            t = (art.get("artifact_type") or "").lower()
            extra = (art.get("extra") or "").lower()

            if self.active_category == "threats":
                if not (("threat_tag" in extra) or ("critical" in extra) or ("tampering" in extra) or ("1102" in extra)):
                    continue
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

            # 2. Search Filter
            if q:
                match_blob = f"{art.get('name', '')} {art.get('path', '')} {art.get('artifact_type', '')} {art.get('extra', '')} {art.get('timestamp', '')}".lower()
                if q not in match_blob:
                    continue

            self.filtered_artifacts.append(art)

        # 3. Sorting
        def sort_key(x):
            val = x.get(self.sort_column) or ""
            return str(val).lower()

        self.filtered_artifacts.sort(key=sort_key, reverse=not self.sort_ascending)

        # 4. Render Rows
        for r in self.main_table.get_children():
            self.main_table.delete(r)

        self.table_count_label.config(text=f"Showing {len(self.filtered_artifacts):,} of {len(self.all_artifacts):,} items")

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
        if not sel:
            return
        art_id = int(sel[0])
        target = next((a for a in self.all_artifacts if a.get("id") == art_id), None)
        if not target:
            return

        # Populate Docked Inspector
        self.ins_selected_title.config(text=f"[ID {target.get('id')}] {target.get('name') or target.get('artifact_type')}")
        self.ins_lbl_type.config(text=f"Artifact Type: {target.get('artifact_type', 'Unknown')}")
        self.ins_lbl_time.config(text=f"Timestamp (UTC): {target.get('timestamp') or target.get('last_access') or 'N/A'}")
        self.ins_lbl_name.config(text=f"Resource Name: {target.get('name') or 'N/A'}")
        self.ins_lbl_path.config(text=f"Full Path: {target.get('path') or 'N/A'}")

        self.ins_txt_extra.delete("1.0", tk.END)
        self.ins_txt_extra.insert(tk.END, target.get("extra") or "None")

        # Threat Context Tab
        self.ins_txt_threat.delete("1.0", tk.END)
        extra_str = target.get("extra") or ""
        if "threat_tag" in extra_str.lower() or "critical" in extra_str.lower() or "tampering" in extra_str.lower():
            self.ins_txt_threat.insert(tk.END, f"🚨 THREAT DETECTION TRIGGERED:\n\n{extra_str}\n\nRecommended Action: Correlate with session timeline to determine process ancestry and network connections.")
        else:
            self.ins_txt_threat.insert(tk.END, "No automated anomaly flags triggered for this forensic event.")

        # Raw JSON Tab
        self.ins_txt_json.delete("1.0", tk.END)
        try:
            details = target.get("details")
            raw_data = json.loads(details) if isinstance(details, str) else (details or target)
            self.ins_txt_json.insert(tk.END, json.dumps(raw_data, indent=2))
        except Exception:
            self.ins_txt_json.insert(tk.END, json.dumps(target, indent=2))

    # --- FORENSIC ACTIONS ---
    def action_live_triage(self):
        self.status_indicator.config(text="● 1-Click Live Triage Running...", foreground=THEME["cyan_accent"])
        threading.Thread(target=self._live_triage_worker, daemon=True).start()

    def _live_triage_worker(self):
        res = core_logic.parse_live_triage_core()
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Live Triage Complete", res.get("message", "Triage finished successfully.")))

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
        self.status_indicator.config(text=f"● Processing Preset '{pid}'...", foreground=THEME["cyan_accent"])
        threading.Thread(target=lambda: self._preset_worker(pid), daemon=True).start()

    def _preset_worker(self, pid):
        res = core_logic.parse_preset_core(pid)
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Preset Complete", res.get("message", "Preset finished.")))

    def action_browse_target(self):
        d = filedialog.askdirectory(title="Select Target Folder or Mounted Forensic Image")
        if d:
            self.target_path_var.set(d)

    def action_scan_target(self):
        p = self.target_path_var.get().strip()
        if not p or not os.path.isdir(p):
            messagebox.showerror("Invalid Path", "Please enter a valid directory path or mounted drive.")
            return
        self.status_indicator.config(text=f"● Auto-Scanning '{p}'...", foreground=THEME["cyan_accent"])
        threading.Thread(target=lambda: self._target_worker(p), daemon=True).start()

    def _target_worker(self, p):
        res = core_logic.parse_target_folder_core(p)
        self.after(0, self.refresh_evidence_data)
        self.after(0, lambda: messagebox.showinfo("Target Scan Finished", res.get("message", "Scan complete.")))

    def action_clear_db(self):
        if messagebox.askyesno("Confirm Database Clear", "Are you sure you want to completely erase the forensic evidence database?\n\nThis will wipe all indexed artifacts and reset SHA-256 integrity."):
            core_logic.clear_database_core()
            self.refresh_evidence_data()
            messagebox.showinfo("Database Cleared", "Evidence database has been successfully wiped clean.")

    def action_export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], title="Export Standard CSV Timeline")
        if p:
            res = core_logic.generate_csv_report(p)
            messagebox.showinfo("CSV Exported", res.get("message", "Done."))

    def action_export_json(self):
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], title="Export DFIR Standard JSON Timeline")
        if p:
            res = core_logic.export_json_report(p)
            messagebox.showinfo("JSON Exported", res.get("message", "Done."))

    def action_export_pdf(self):
        p = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Export Forensic Audit PDF Report")
        if p:
            meta = {
                "caseNumber": "CASE-2026-DESKTOP",
                "evidenceNumber": "EVID-001-WIN-HOST",
                "examiner": os.environ.get("USERNAME", "Forensic Examiner"),
                "uniqueDescription": "Windows User Activity & Attack Timeline Reconstruction",
                "notes": "Automated forensic audit generated via AegisDFIR Workstation."
            }
            res = core_logic.generate_pdf_report_core(p, meta)
            messagebox.showinfo("PDF Generated", res.get("message", "Done."))

    # --- MODAL 1: VISUAL ANALYTICS (MATPLOTLIB IN TKINTER) ---
    def open_visual_analytics_modal(self):
        win = tk.Toplevel(self)
        win.title("AegisDFIR - Visual Forensics & Analytics Dashboard")
        win.geometry("1150x740")
        win.configure(background=THEME["bg_surface"])

        fig = plt.Figure(figsize=(11.5, 7.2), facecolor=THEME["bg_surface"])
        
        # 1. Timeline Activity Bar
        ax1 = fig.add_subplot(2, 2, (1, 2))
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
            ax1.bar(sorted_days, day_counts, color=THEME["cyan_accent"], edgecolor=THEME["blue_accent"], alpha=0.85)
            ax1.set_title("⏱️ Chronological Activity Density (Events Timeline)", color=THEME["text_primary"], fontsize=11, fontweight="bold")
            ax1.tick_params(colors=THEME["text_secondary"], labelsize=9, rotation=30)
        else:
            ax1.text(0.5, 0.5, "No Timestamped Evidence Available", color=THEME["text_muted"], ha="center", va="center", fontsize=11)

        # 2. Category Donut
        ax2 = fig.add_subplot(2, 2, 3)
        ax2.set_facecolor(THEME["bg_surface"])
        cat_counts = {}
        for art in self.all_artifacts:
            t = art.get("artifact_type") or "Unknown"
            cat_counts[t] = cat_counts.get(t, 0) + 1

        top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        if top_cats:
            ax2.pie([c[1] for c in top_cats], labels=[c[0] for c in top_cats], textprops={"color": THEME["text_primary"], "fontsize": 9},
                    wedgeprops={"edgecolor": THEME["bg_surface"], "width": 0.5})
            ax2.set_title("📦 Evidence Category Breakdown", color=THEME["text_primary"], fontsize=11, fontweight="bold")
        else:
            ax2.text(0.5, 0.5, "No Categories", color=THEME["text_muted"], ha="center", va="center", fontsize=11)

        # 3. Top Apps Bar
        ax3 = fig.add_subplot(2, 2, 4)
        ax3.set_facecolor(THEME["bg_elevated"])
        app_counts = {}
        for art in self.all_artifacts:
            t = (art.get("artifact_type") or "").lower()
            if "prefetch" in t or "userassist" in t or "bam" in t:
                name = art.get("name") or "Unknown"
                app_counts[name] = app_counts.get(name, 0) + 1

        top_apps = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_apps:
            ax3.barh([a[0] for a in top_apps][::-1], [a[1] for a in top_apps][::-1], color=THEME["green_accent"], alpha=0.85)
            ax3.set_title("🚀 Top Executed Applications", color=THEME["text_primary"], fontsize=11, fontweight="bold")
            ax3.tick_params(colors=THEME["text_secondary"], labelsize=9)
        else:
            ax3.text(0.5, 0.5, "No Execution Records", color=THEME["text_muted"], ha="center", va="center", fontsize=11)

        fig.tight_layout(pad=2.4)
        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # --- MODAL 2: RECONSTRUCTED SESSION TIMELINE ---
    def open_timeline_window(self):
        win = tk.Toplevel(self)
        win.title("AegisDFIR - Reconstructed Cross-Artifact Session Timeline")
        win.geometry("1150x680")
        win.configure(background=THEME["bg_surface"])

        top_bar = ttk.Frame(win, style="Elevated.TFrame", padding=(12, 8))
        top_bar.pack(fill=tk.X)

        ttk.Label(top_bar, text="⏱️ Multi-Vector Correlated Event Sequence", font=FONT_TITLE, foreground=THEME["cyan_accent"], background=THEME["bg_elevated"]).pack(side=tk.LEFT)

        cols = ("time", "session", "type", "detail", "anomaly", "mitre")
        timeline_tree = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        
        headers = {
            "time": ("Timestamp (UTC)", 160),
            "session": ("Session", 80),
            "type": ("Artifact Type", 140),
            "detail": ("Reconstructed Action Detail", 380),
            "anomaly": ("Anomaly Indicator", 190),
            "mitre": ("MITRE ATT&CK", 130)
        }
        for k, (txt, w) in headers.items():
            timeline_tree.heading(k, text=txt)
            timeline_tree.column(k, width=w)

        timeline_tree.tag_configure("anomaly", background="#451A1A", foreground="#FCA5A5")

        vsb = ttk.Scrollbar(win, orient=tk.VERTICAL, command=timeline_tree.yview)
        timeline_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        timeline_tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        corrs = core_logic.get_correlations_json()
        for item in corrs:
            has_anomaly = bool(item.get("anomaly"))
            tag = "anomaly" if has_anomaly else ""
            timeline_tree.insert("", tk.END, values=(
                item.get("timestamp"),
                f"S-{item.get('session', 1)}",
                item.get("artifact_type"),
                item.get("detail"),
                item.get("anomaly") or "Normal",
                item.get("mitre") or "-"
            ), tags=(tag,) if tag else ())

if __name__ == "__main__":
    app = AegisDFIRDesktopApp()
    app.mainloop()
