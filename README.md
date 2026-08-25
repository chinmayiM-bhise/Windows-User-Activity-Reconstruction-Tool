# 🐾 Footprint Analyzer - Windows Forensic Artifacts Parser & User Activity Reconstruction Platform (v1.3.4)

[![CI](https://github.com/chinmayiM-bhise/Windows-User-Activity-Reconstruction-Tool/actions/workflows/ci.yml/badge.svg)](https://github.com/chinmayiM-bhise/Windows-User-Activity-Reconstruction-Tool/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![DFIR Standard](https://img.shields.io/badge/Forensics-DFIR%20Timeline%20Ready-brightgreen)](https://github.com/chinmayiM-bhise/Windows-User-Activity-Reconstruction-Tool)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-0078D6?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Footprint Analyzer** is an automated, enterprise-grade Digital Forensics and Incident Response (DFIR) platform designed to parse, correlate, and reconstruct user activity and attack timelines from Windows operating systems, live triage, and mounted forensic images. Discovers and parses 12+ artifact types, correlates multi-vector attack chains (Download → Run → Anti-Forensics) with MITRE ATT&CK tagging, and exports compliance-ready **DFIR JSON Timelines**, **Standardized CSVs**, and **Enterprise PDF Forensic Audit Reports**.

---

## ⚡ 1-Click Cloud Launch

Launch and explore the platform directly in your browser without installing anything locally:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/chinmayiM-bhise/Windows-User-Activity-Reconstruction-Tool)

---

## 🏛️ System Architecture

```mermaid
graph TD
    A1[Live Windows Host] --> B[Smart Path Resolver & Auto-Discovery Engine]
    A2[Mounted Forensic Image / Drive Letter] --> B
    A3[KAPE / Velociraptor / Triage Archive] --> B

    B -->|Prefetch / .pf| C1[Prefetch Parser - Execution Counts & Volumes]
    B -->|Recent & Desktop / .lnk| C2[LNK Shortcut Parser - Targets & Serial IDs]
    B -->|Recycle.Bin / $I| C3[Recycle Bin Parser - File Deletions & Original Paths]
    B -->|Registry BagMRU| C4[ShellBags Parser - Folder Navigation & Network Shares]
    B -->|Chrome / Edge / Firefox| C5[Browser Parser - URLs & Download Provenance]
    B -->|PSReadLine / ConsoleHost| C6[PowerShell Parser - CLI Syntax & Threat Heuristics]
    B -->|Registry UserAssist ROT13| C7[UserAssist Parser - GUI App Runs & Focus Duration]
    B -->|USBSTOR & MountedDevices| C8[USB Device Parser - Hardware IDs & Drive Letters]
    B -->|BAM / DAM Kernel Service| C9[BAM Parser - Per-User SID Executables]
    B -->|Run / RunOnce / Startup| C10[Startup Parser - Persistence Mechanisms]
    B -->|Security & System EVTX| C11[EVTX Parser - Logons, Process Spawns & Tampering]
    B -->|Destinations-ms| C12[JumpList Parser - Recent Application Documents]

    C1 & C2 & C3 & C4 & C5 & C6 & C7 & C8 & C9 & C10 & C11 & C12 --> D[(Forensic Storage Engine - SQLite DB with SHA-256)]

    D --> E[Multi-Vector Forensic Correlator]
    E -->|Temporal Sessionizer| F1[User Session Timeline]
    E -->|Download-to-Run Pipeline| F2[Malware Staging Correlation]
    E -->|Suspicious Paths & Tampering| F3[Threat & Anti-Forensics Alerter]
    E -->|MITRE ATT&CK Matrix| F4[Tactic & Technique Tagging]

    F1 & F2 & F3 & F4 --> G1[Next-Gen Multi-Pane Web Dashboard]
    F1 & F2 & F3 & F4 --> G2[Enterprise PDF Audit Report]
    F1 & F2 & F3 & F4 --> G3[DFIR Standard JSON Timeline & CSV]
    F1 & F2 & F3 & F4 --> G4[Native Desktop Tkinter GUI]
```

---

## ✨ Key Capabilities

| Engine | Module | Description |
| :--- | :--- | :--- |
| **Smart Path Resolver** | [`path_resolver.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/path_resolver.py) | Auto-resolves live Windows paths (`%SystemRoot%`, `%APPDATA%`) and recursively crawls mounted drives (`E:\`) and triage dumps without manual path entry. |
| **Browser Forensics** | [`browser_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/browser_parser.py) | Parses Chrome, Edge, Brave, Opera, and Firefox SQLite databases for visited URLs, page titles, visit counts, and file downloads with safe lock handling. |
| **PowerShell Threat Hunter** | [`powershell_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/powershell_parser.py) | Recovers full `ConsoleHost_history.txt` commands and flags IEX, encoded commands, web cradles, Mimikatz, and shadow copy deletion. |
| **UserAssist Decoder** | [`userassist_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/userassist_parser.py) | Decodes ROT13 Registry keys to extract GUI program execution counts, application focus counts, and active focus time in seconds. |
| **USB & Storage Tracker** | [`usb_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/usb_parser.py) | Reconstructs USBSTOR device history, serial numbers, vendor/product descriptors, volume GUIDs, and assigned drive letters. |
| **Kernel Execution Monitor** | [`bam_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/bam_parser.py) | Parses Windows Background Activity Moderator (BAM/DAM) for kernel-verified executable paths and last run times per User SID. |
| **Security Event Auditor** | [`evtx_parser.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/evtx_parser.py) | Analyzes Logon (4624/4625), Process Spawns (4688), New Services (7045), PowerShell Script Blocks (4104), and Log Cleared alerts (1102). |
| **Multi-Vector Correlator** | [`correlator.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/correlator.py) | Chains multi-stage attacks (e.g. Browser Download → Temp Execution → Log Tampering) into sessionized timelines with MITRE ATT&CK tags. |
| **Enterprise Reporter** | [`report_gen.py`](file:///D:/Github%20projects/windows-artifacts-parser-v1.2.8/windows-artifacts-parser/parsers/report_gen.py) | Generates publication-ready executive PDF audit reports with SHA-256 database verification, examiner metadata, and timeline activity charts. |

---

## 🚀 Quickstart Guide

### Option 1: Run Modern Cyber Web Dashboard (Recommended)

#### 1. Setup & Installation
```bash
# Clone the repository
git clone https://github.com/chinmayiM-bhise/Windows-User-Activity-Reconstruction-Tool.git
cd Windows-User-Activity-Reconstruction-Tool

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate  # On Linux/macOS: source venv/bin/activate

# Install forensic dependencies
pip install -r requirements.txt
```

#### 2. Launch Web Server
```bash
python app.py
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser.

---

### Option 2: Run Native Desktop GUI

For standalone native Windows desktop analysis without a web browser:

```bash
python main.py
```

---

## 💻 Enterprise CLI Usage

For headless automation, triage scripts, or CI/CD pipelines:

```bash
# Run 1-Click Live System Triage
python -c "import core_logic; res = core_logic.parse_live_triage_core(); print(res['message'])"

# Intelligently scan an external mounted drive or triage directory
python -c "import core_logic; res = core_logic.parse_target_folder_core(r'E:\ForensicDump'); print(res['message'])"

# Export standard reports
python -c "import core_logic; core_logic.generate_csv_report('timeline.csv'); core_logic.export_json_report('timeline.json')"
```

### Generated Audit Artifacts:
- `AegisDFIR_Audit_Report.pdf` — Publication-ready executive forensic security report with SHA-256 verification.
- `timeline.json` — Machine-readable DFIR Standard JSON timeline.
- `timeline.csv` — Standardized CSV for Excel and Timeline Explorer.

---

## 🔍 Real-World Compatibility Matrix

| Forensic Artifact Category | Standard Windows Location | Forensic Significance | Status |
| :--- | :--- | :--- | :---: |
| **Prefetch Files** | `%SystemRoot%\Prefetch\*.pf` | Binary execution, run counts, volume info, timestamps | ✅ Supported |
| **Shortcut (LNK) Files** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | File access, target volume serials, creation dates | ✅ Supported |
| **Recycle Bin Metadata** | `%SystemDrive%\$Recycle.Bin\*\$I*` | Deleted file recovery, original paths, deletion time | ✅ Supported |
| **Explorer ShellBags** | `HKCU\Software\Microsoft\Windows\Shell\BagMRU` | Folder navigation history (local, network, removable) | ✅ Supported |
| **Web Browsers** | Chrome, Edge, Brave, Opera `History`, Firefox `places.sqlite` | Visited URLs, search queries, download provenance | ✅ Supported |
| **PowerShell History** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\*.txt` | Attacker CLI commands, encoded payloads, Lolbins | ✅ Supported |
| **UserAssist (ROT13)** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI app execution count, focus time, last run date | ✅ Supported |
| **USB & Storage Devices** | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `MountedDevices` | USB device connection history, serials, drive letters | ✅ Supported |
| **BAM / DAM Kernel Monitor** | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` | Kernel-level executable execution per User SID | ✅ Supported |
| **Startup & Autoruns** | `HKLM\...\Run`, `HKCU\...\Run`, Startup Folders | Persistence mechanisms, malicious startup entries | ✅ Supported |
| **Windows Event Logs** | `%SystemRoot%\System32\Winevt\Logs\*.evtx` | Logons (4624/4625), process spawns, log clearing (1102) | ✅ Supported |
| **Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations` | Recent files and documents opened per application | ✅ Supported |

---

## 🧪 Running Automated Tests

```bash
pytest -v
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more information.
