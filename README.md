# Windows Artifacts Parser

A professional-grade Digital Forensics and Incident Response (DFIR) tool designed to parse and analyze critical Windows artifacts. This tool provides both a desktop GUI and a web-based interface for extracting actionable intelligence from Windows systems.

## 🚀 Features

- **Multi-Artifact Parsing**: Supports extraction and analysis of:
  - **Prefetch Files**: Track application execution history.
  - **LNK Files (Shortcuts)**: Identify file access and program execution.
  - **Recycle Bin**: Recover deleted file metadata ($I and $R files).
  - **Shellbags**: Reconstruct folder browsing history.
- **Dual Interface**:
  - **Desktop GUI**: Built with Tkinter for local, native performance.
  - **Web Dashboard**: Modern Flask-based API and frontend for remote or browser-based analysis.
- **Comprehensive Reporting**:
  - **PDF Reports**: Professional forensic reports including data visualizations (charts).
  - **CSV Export**: Standardized data format for further analysis in tools like Excel or Timeline Explorer.
- **Forensic Integrity**:
  - SHA256 hashing of databases.
  - Metadata logging (Examiner, Source Host, OS details).
  - SQLite-backed storage for persistence and SQL-based querying.

## 🛠️ Tech Stack

- **Language**: Python 3.x
- **GUI**: Tkinter / CustomTkinter
- **Web**: Flask, JavaScript, HTML/CSS
- **Data Handling**: Pandas, SQLite3
- **Forensics Libraries**: `pylnk3`, `pefile`
- **Visualization**: Matplotlib, ReportLab (PDF generation)

## 📋 Prerequisites

- Windows OS (for target artifact parsing)
- Python 3.10+
- Administrative privileges (required to access certain system artifacts like Prefetch)

## ⚙️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/windows-artifacts-parser.git
   cd windows-artifacts-parser
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🖥️ Usage

### Desktop GUI
Run the main orchestrator:
```bash
python main.py
```

### Web Interface
Start the Flask server:
```bash
python app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser.

## 📂 Project Structure

- `parsers/`: Modular logic for individual artifact types.
- `db/`: Database schema and utility functions.
- `web/`: Frontend assets for the web dashboard.
- `reports/`: Default output directory for generated PDF reports.
- `app.py`: Flask application entry point.
- `main.py`: Tkinter application entry point.

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Disclaimer: This tool is intended for educational and forensic analysis purposes. Always ensure you have proper authorization before analyzing a system.*
