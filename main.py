# main.py
"""
Main GUI and orchestration for Windows Artifacts Parser.
Includes:
- parsing flows for prefetch/lnk/recycle/shellbags (calls out to parsers modules)
- DB integration (uses open_db/execute_with_retry if available)
- Report generation (PDF) with charts
- CSV export
"""

import os
import sqlite3
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import tempfile
import getpass
import platform
import socket
import datetime
import hashlib
import matplotlib

# Use Agg backend for non-GUI chart rendering
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Try to import db_utils either in package or root
try:
    from db.db_utils import open_db, execute_with_retry
except Exception:
    try:
        from db_utils import open_db, execute_with_retry
    except Exception:
        open_db = None
        execute_with_retry = None

# Import parsers and schema (try package imports then fallbacks)
try:
    from parsers import report_gen, prefetch_parser, lnk_parser, recycle_parser, shellbags_parser
except Exception:
    # fallback: maybe modules are at top-level
    import report_gen
    import prefetch_parser
    import lnk_parser
    import recycle_parser
    import shellbags_parser

# schema functions - attempt package then fallback
try:
    from db.schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk
except Exception:
    try:
        from schema import init_db, insert_artifact, query_artifacts, insert_artifacts_bulk
    except Exception:
        # Last resort: import db.schema as module
        import db.schema as schema
        init_db = schema.init_db
        insert_artifact = schema.insert_artifact
        query_artifacts = schema.query_artifacts
        insert_artifacts_bulk = schema.insert_artifacts_bulk

DB_PATH = "artifacts.db"
TOOL_VERSION = "v1.2.4"


def _sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def build_metadata(db_path: str) -> dict:
    meta = {}
    try:
        meta["Examiner"] = getpass.getuser()
    except Exception:
        meta["Examiner"] = ""
    try:
        meta["Source"] = socket.gethostname()
    except Exception:
        meta["Source"] = ""
    meta["OS"] = f"{platform.system()} {platform.release()} ({platform.version()})"
    meta["Tool Version"] = TOOL_VERSION
    meta["Generated"] = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    meta["DB SHA256"] = _sha256_file(db_path)
    meta["Case ID"] = ""
    meta["Notes"] = ""
    return meta


def _make_counts_chart(rows, outpath):
    types = [r.get("artifact_type") or "unknown" for r in rows]
    counts = {}
    for t in types:
        counts[t] = counts.get(t, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    labels = [i[0] for i in items]
    values = [i[1] for i in items]

    fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
    color_count = max(1, len(labels))
    try:
        colors_map = plt.cm.Set2.colors
        color_list = colors_map[:color_count]
    except Exception:
        color_list = None

    bars = ax.bar(range(len(labels)), values, color=color_list)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Count")
    ax.set_title("Artifact counts by type")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    for rect in bars:
        height = rect.get_height()
        ax.annotate(str(int(height)), xy=(rect.get_x() + rect.get_width() / 2, height), xytext=(0, 2), textcoords="offset points", ha="center", va="bottom", fontsize=7)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)


def _make_timeline_histogram(rows, outpath):
    times = []
    for r in rows:
        t = r.get("timestamp") or r.get("last_access")
        if not t:
            continue
        try:
            s = t
            if s.endswith("Z"):
                s = s[:-1]
            dt = datetime.datetime.fromisoformat(s)
            times.append(dt)
        except Exception:
            continue

    if not times:
        fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
        ax.text(0.5, 0.5, "No timestamp data available for timeline", ha="center", va="center", fontsize=10)
        ax.axis("off")
        fig.savefig(outpath, bbox_inches="tight")
        plt.close(fig)
        return

    timestamps = [dt.timestamp() for dt in times]
    fig, ax = plt.subplots(figsize=(6.5, 2.6), dpi=150)
    ax.hist(timestamps, bins=24, color="#5DA5A4", edgecolor="white")
    ax.set_title("Events over time (histogram)")
    xlocs = ax.get_xticks()
    xlabels = [datetime.datetime.utcfromtimestamp(x).strftime("%Y-%m-%d\n%H:%M") for x in xlocs]
    ax.set_xticklabels(xlabels, rotation=45, ha="right", fontsize=7)
    ax.set_xlabel("UTC")
    ax.set_ylabel("Events")
    ax.grid(axis="y", linestyle="--", alpha=0.3)
    plt.tight_layout()
    fig.savefig(outpath, bbox_inches="tight")
    plt.close(fig)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Windows Artifacts Parser")
        self.geometry("1100x700")
        self.resizable(True, True)
        self.setup_styles()
        init_db(DB_PATH)
        self.create_widgets()

    def setup_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        BG_COLOR = "#FBFBFA"
        TEXT_COLOR = "#090E0A"
        MUTED_GREEN_GRAY = "#5C635B"
        GOLD_ACCENT = "#B09861"
        LIGHT_BEIGE_HOVER = "#CACDAE"
        SEPARATOR_COLOR = "#EAEAEA"
        self.configure(background=BG_COLOR)
        style.configure(".", background=BG_COLOR, foreground=TEXT_COLOR, font=("Segoe UI", 9))
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=TEXT_COLOR)
        style.configure("TButton", background=GOLD_ACCENT, foreground=BG_COLOR, font=("Segoe UI", 9, "bold"), borderwidth=0, padding=(14, 8))
        style.map("TButton", background=[("active", LIGHT_BEIGE_HOVER), ("hover", MUTED_GREEN_GRAY)], foreground=[("active", TEXT_COLOR), ("hover", BG_COLOR)])
        style.configure("TEntry", fieldbackground="#FFFFFF", foreground=TEXT_COLOR, insertcolor=TEXT_COLOR, bordercolor=SEPARATOR_COLOR, borderwidth=1, padding=8)
        style.configure("Treeview", rowheight=30, fieldbackground=BG_COLOR, background=BG_COLOR, foreground=TEXT_COLOR, borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", background=BG_COLOR, foreground=MUTED_GREEN_GRAY, font=("Segoe UI", 10, "bold"), padding=(10, 10), relief="flat", bordercolor=SEPARATOR_COLOR, borderwidth=1)
        self.tree_tags = {"odd": BG_COLOR, "even": "#F5F5F5", "hover": LIGHT_BEIGE_HOVER}

    def create_widgets(self):
        main_frame = ttk.Frame(self, padding=(20, 10))
        main_frame.pack(fill=tk.BOTH, expand=True)
        title_label = ttk.Label(main_frame, text="Windows Artifacts Parser", font=("Segoe UI", 20, "bold"), anchor="w")
        title_label.pack(fill=tk.X, pady=(0, 20))
        top = ttk.Frame(main_frame)
        top.pack(fill=tk.X, pady=(0, 15))
        self.path_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.path_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
        ttk.Button(top, text="Browse...", command=self.browse_folder).pack(side=tk.LEFT, padx=(8, 4))
        ttk.Button(top, text="Parse Folder", command=self.parse_selected).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Parse ShellBags", command=self.parse_shellbags).pack(side=tk.LEFT, padx=4)
        tree_container = ttk.Frame(main_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        cols = ("id", "type", "name", "path", "timestamp", "last_access", "extra")
        self.tree = ttk.Treeview(tree_container, columns=cols, show="headings")
        self.tree.tag_configure("oddrow", background=self.tree_tags["odd"])
        self.tree.tag_configure("evenrow", background=self.tree_tags["even"])
        self.tree.tag_configure("hover", background=self.tree_tags["hover"])
        self._hovered_item = None
        self.tree.bind("<Motion>", self._on_hover)
        self.tree.bind("<Leave>", self._on_leave)
        for c in cols:
            self.tree.heading(c, text=c.capitalize(), anchor=tk.W)
            self.tree.column(c, width=150 if c not in ("extra", "path") else 300, anchor=tk.W)
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        bottom = ttk.Frame(main_frame)
        bottom.pack(fill=tk.X, pady=(15, 0))
        ttk.Button(bottom, text="Correlate / Timeline", command=self.open_correlator).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Refresh", command=self.refresh_view).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export to CSV", command=self.export_to_csv).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export PDF Report", command=self.export_pdf_report).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export Correlation PDF", command=lambda: self.export_correlation_pdf(None)).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Clear DB", command=self.clear_db).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Exit", command=self.destroy).pack(side=tk.RIGHT)
        self.refresh_view()

    # --- GUI hover helpers ---
    def _on_hover(self, event):
        item = self.tree.identify_row(event.y)
        if item != self._hovered_item:
            if self._hovered_item:
                tags = list(self.tree.item(self._hovered_item, "tags"))
                if "hover" in tags:
                    tags.remove("hover")
                    self.tree.item(self._hovered_item, tags=tags)
            if item:
                tags = list(self.tree.item(item, "tags"))
                if "hover" not in tags:
                    tags.append("hover")
                self.tree.item(item, tags=tags)
            self._hovered_item = item

    def _on_leave(self, event):
        if self._hovered_item:
            tags = list(self.tree.item(self._hovered_item, "tags"))
            if "hover" in tags:
                tags.remove("hover")
                self.tree.item(self._hovered_item, tags=tags)
        self._hovered_item = None

    # --- file/folder handling ---
    def browse_folder(self):
        d = filedialog.askdirectory(title="Select Folder Containing Artifacts")
        if d:
            self.path_var.set(d)

    def parse_selected(self):
        folder = self.path_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please choose a valid directory to parse.")
            return
        threading.Thread(target=self._parse_folder, args=(folder,), daemon=True).start()
        messagebox.showinfo("Parsing Started", "Parsing in background. Click Refresh when finished.")

    def _parse_folder(self, folder):
        conn = None
        if open_db:
            conn = open_db(DB_PATH)
        else:
            conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        for root, _, files in os.walk(folder):
            root_lower = root.lower()
            for f in files:
                path = os.path.join(root, f)
                low = f.lower()
                try:
                    if low.endswith(".pf") or "prefetch" in root_lower:
                        for rec in prefetch_parser.parse_prefetch(path):
                            insert_artifact(conn, rec)
                    elif low.endswith(".lnk"):
                        for rec in lnk_parser.parse_lnk(path):
                            insert_artifact(conn, rec)
                    elif (low.startswith("$i") or low.startswith("i")) and ("$recycle.bin" in root_lower or "recycle.bin" in root_lower):
                        for rec in recycle_parser.parse_i_file(path):
                            insert_artifact(conn, rec)
                except Exception as e:
                    print(f"[!] Failed to parse {path}: {e}")
        try:
            conn.commit()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        print("[+] Parsing complete.")
        self.after(0, lambda: messagebox.showinfo("Parsing Complete", f"Finished parsing folder: {folder}"))
        self.after(0, self.refresh_view)

    # --- ShellBags parse worker ---
    def parse_shellbags(self):
        if hasattr(self, "_shellbags_thread") and self._shellbags_thread.is_alive():
            messagebox.showwarning("ShellBags", "ShellBags parsing is already running.")
            return
        self._shellbags_thread = threading.Thread(target=self._parse_shellbags_worker, daemon=True)
        self._shellbags_thread.start()
        messagebox.showinfo("ShellBags", "Parsing ShellBags in background. Click Refresh when finished.")

    def _parse_shellbags_worker(self):
        try:
            records = shellbags_parser.parse_shellbags()
            if not records:
                self.after(0, lambda: messagebox.showinfo("ShellBags", "No ShellBag data found or insufficient privileges."))
                return
            conn = open_db(DB_PATH) if open_db else sqlite3.connect(DB_PATH)
            insert_artifacts_bulk(conn, records)
            try:
                conn.commit()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            self.after(0, self.refresh_view)
            self.after(0, lambda: messagebox.showinfo("ShellBags", f"Parsed and inserted {len(records)} ShellBag entries."))
        except Exception as e:
            err_text = f"Failed to parse ShellBags:\n{e}"
            # capture err_text so lambda closure works
            self.after(0, lambda msg=err_text: messagebox.showerror("Error", msg))
            print(f"[!] ShellBags worker error: {e}")

    # --- view / DB operations ---
    def refresh_view(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        rows = query_artifacts(DB_PATH)
        for i, row in enumerate(rows):
            row = dict(row)
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            self.tree.insert("", tk.END, values=(row.get("id"), row.get("artifact_type"), row.get("name"), row.get("path"), row.get("timestamp"), row.get("last_access"), row.get("extra")), tags=(tag,))

    def clear_db(self):
        if messagebox.askyesno("Confirm", "Delete all artifacts from the database?"):
            conn = open_db(DB_PATH) if open_db else sqlite3.connect(DB_PATH)
            try:
                if execute_with_retry:
                    execute_with_retry(conn, "DELETE FROM artifacts")
                else:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM artifacts")
                    conn.commit()
            except Exception as e:
                print(f"[!] Error clearing DB: {e}")
            try:
                conn.close()
            except Exception:
                pass
            self.refresh_view()

    # --- CSV export (NEW method) ---
    def export_to_csv(self):
        """
        Export all artifacts to CSV. Opens a SaveAs dialog for destination.
        """
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")], title="Export artifacts as CSV")
        if not path:
            return
        try:
            rows = query_artifacts(DB_PATH)
            # rows are sqlite.Row-like or dict-like
            # Determine CSV header from keys of first row
            if not rows:
                messagebox.showinfo("Export CSV", "No artifacts to export.")
                return
            first = dict(rows[0])
            headers = list(first.keys())
            with open(path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                for r in rows:
                    rowd = dict(r)
                    writer.writerow([rowd.get(h) for h in headers])
            messagebox.showinfo("Export CSV", f"Export complete: {path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export CSV:\n{e}")

    # --- PDF export with metadata + charts ---
    def export_pdf_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")], title="Export Artifacts Report as PDF")
        if not file_path:
            return
        try:
            rows = query_artifacts(DB_PATH)
            metadata = build_metadata(DB_PATH)
            tmp_dir = tempfile.mkdtemp(prefix="wab_report_")
            counts_png = os.path.join(tmp_dir, "counts.png")
            timeline_png = os.path.join(tmp_dir, "timeline.png")
            _make_counts_chart(rows, counts_png)
            _make_timeline_histogram(rows, timeline_png)
            metadata["chart_counts"] = counts_png
            metadata["chart_timeline"] = timeline_png
            report_gen.generate_pdf_report(DB_PATH, file_path, title=f"Artifacts Report ({socket.gethostname()})", metadata=metadata)
            messagebox.showinfo("Report Generated", f"PDF report successfully generated:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate PDF report:\n{e}")

    def export_correlation_pdf(self, parent_window=None):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")], title="Export Correlation Report to PDF", parent=parent_window)
        if not file_path:
            return
        try:
            rows = query_artifacts(DB_PATH)
            metadata = build_metadata(DB_PATH)
            tmp_dir = tempfile.mkdtemp(prefix="wab_corr_")
            counts_png = os.path.join(tmp_dir, "counts_corr.png")
            timeline_png = os.path.join(tmp_dir, "timeline_corr.png")
            _make_counts_chart(rows, counts_png)
            _make_timeline_histogram(rows, timeline_png)
            metadata["chart_counts"] = counts_png
            metadata["chart_timeline"] = timeline_png
            report_gen.generate_correlation_pdf(DB_PATH, file_path, title=f"Correlation Report ({socket.gethostname()})", metadata=metadata)
            messagebox.showinfo("Report Generated", f"Correlation PDF successfully generated:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate correlation PDF:\n{e}")

    # --- Correlator UI ---
    def open_correlator(self):
        window = tk.Toplevel(self)
        window.title("Correlations / Timeline")
        window.geometry("1200x650")
        window.configure(background="#FBFBFA")
        main_frame = ttk.Frame(window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(6, 8))
        ttk.Button(toolbar, text="Export Correlation PDF", command=lambda: self.export_correlation_pdf(window)).pack(side=tk.LEFT)
        cols = ("time", "artifact", "detail", "anomaly")
        tree = ttk.Treeview(main_frame, columns=cols, show="headings", height=20)
        tree.heading("time", text="Timestamp", anchor=tk.W)
        tree.heading("artifact", text="Type", anchor=tk.W)
        tree.heading("detail", text="Detail", anchor=tk.W)
        tree.heading("anomaly", text="Anomaly", anchor=tk.W)
        tree.column("time", width=180, anchor=tk.W)
        tree.column("artifact", width=150, anchor=tk.W)
        tree.column("detail", width=700, anchor=tk.W)
        tree.column("anomaly", width=200, anchor=tk.W)
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(main_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)
        tree.tag_configure("evenrow", background="#F5F5F5")
        tree.tag_configure("oddrow", background="#FBFBFA")

        # Attempt to import correlate_artifacts; support both styles
        try:
            from correlator import correlate_artifacts
        except Exception:
            try:
                # maybe the function expects a DB connection
                from correlator import correlate_artifacts
            except Exception as e:
                messagebox.showerror("Correlator Error", f"Failed to import correlator: {e}")
                return

        # correlate_artifacts may expect DB path or connection; handle both
        rows = []
        try:
            rows = correlate_artifacts(DB_PATH)
        except TypeError:
            # assume it expects a sqlite3 connection
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            try:
                rows = correlate_artifacts(conn)
            finally:
                conn.close()
        except Exception as e:
            messagebox.showerror("Correlator Error", f"Correlator failed: {e}")
            return

        for i, r in enumerate(rows):
            tag = "evenrow" if i % 2 == 0 else "oddrow"
            tree.insert("", tk.END, values=(r.get("timestamp") or "", r.get("artifact_type") or "", r.get("detail") or "", r.get("anomaly") or ""), tags=(tag,))


if __name__ == "__main__":
    app = App()
    app.mainloop()
