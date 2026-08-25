# parsers/path_resolver.py
r"""
Smart Artifact Path Resolver & Triage Auto-Discovery Engine.
Provides:
- Comprehensive catalog of Windows forensic artifacts with descriptions and forensic value.
- Live system auto-detection (resolves environment variables like %SystemRoot%, %LocalAppData%, %APPDATA%).
- Offline / Triage Image Auto-Scanner: crawls any mounted forensic image, drive letter (E:\),
  or KAPE/Velociraptor dump and automatically categorizes every detected artifact.
"""

import os
import glob
import re
from typing import List, Dict, Any, Optional

# Forensic Artifact Catalog with metadata, default live paths, and file matching signatures
ARTIFACT_CATALOG = [
    {
        "id": "prefetch",
        "name": "Windows Prefetch",
        "category": "Program Execution",
        "icon": "rocket",
        "description": "Proves application execution history, execution counts, timestamps, and referenced files.",
        "live_paths": [
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        ],
        "file_patterns": ["*.pf"],
        "folder_patterns": ["prefetch"],
        "requires_admin": True,
    },
    {
        "id": "lnk",
        "name": "Shortcut / LNK Files",
        "category": "File Access",
        "icon": "link",
        "description": "Identifies files, folders, and applications opened by the user, target paths, drive serials, and timestamps.",
        "live_paths": [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent"),
            os.path.join(os.environ.get("USERPROFILE", ""), r"Desktop"),
        ],
        "file_patterns": ["*.lnk"],
        "folder_patterns": ["recent", "desktop", "start menu"],
        "requires_admin": False,
    },
    {
        "id": "recycle_bin",
        "name": "Recycle Bin ($I / $R)",
        "category": "Deleted Files",
        "icon": "trash",
        "description": "Recovers deleted file metadata ($I index files) including original full path, deletion timestamp, and file size.",
        "live_paths": [
            os.path.join(os.environ.get("SystemDrive", "C:"), r"\$Recycle.Bin"),
        ],
        "file_patterns": ["$i*", "i*"],
        "folder_patterns": ["$recycle.bin", "recycle.bin"],
        "requires_admin": True,
    },
    {
        "id": "shellbags",
        "name": "Explorer ShellBags",
        "category": "File Access",
        "icon": "folder",
        "description": "Reconstructs folder browsing history across local drives, network shares, removable media, and deleted folders.",
        "live_paths": ["REGISTRY:HKCU\\Software\\Microsoft\\Windows\\Shell\\BagMRU"],
        "file_patterns": ["usrclass.dat", "ntuser.dat"],
        "folder_patterns": ["shell"],
        "requires_admin": False,
    },
    {
        "id": "browser_history",
        "name": "Web Browsers (Chrome / Edge / Firefox)",
        "category": "Web Activity",
        "icon": "globe",
        "description": "Extracts visited URLs, web searches, download history, and timestamps from Chrome, Edge, Brave, Opera, and Firefox.",
        "live_paths": [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Google\Chrome\User Data\Default\History"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Edge\User Data\Default\History"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"BraveSoftware\Brave-Browser\User Data\Default\History"),
            os.path.join(os.environ.get("APPDATA", ""), r"Opera Software\Opera Stable\History"),
            os.path.join(os.environ.get("APPDATA", ""), r"Mozilla\Firefox\Profiles"),
        ],
        "file_patterns": ["history", "places.sqlite", "downloads.sqlite"],
        "folder_patterns": ["chrome", "edge", "brave", "firefox", "opera"],
        "requires_admin": False,
    },
    {
        "id": "powershell_history",
        "name": "PowerShell Command History",
        "category": "Command Execution",
        "icon": "terminal",
        "description": "Extracts full commands entered in PowerShell (PSReadLine) and flags malicious/suspicious CLI syntax.",
        "live_paths": [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        ],
        "file_patterns": ["consolehost_history.txt"],
        "folder_patterns": ["psreadline", "powershell"],
        "requires_admin": False,
    },
    {
        "id": "userassist",
        "name": "UserAssist (GUI Execution)",
        "category": "Program Execution",
        "icon": "activity",
        "description": "Registry ROT13-encoded tracking of GUI executable execution counts, focus count, focus duration, and last run time.",
        "live_paths": ["REGISTRY:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"],
        "file_patterns": ["ntuser.dat"],
        "folder_patterns": ["userassist"],
        "requires_admin": False,
    },
    {
        "id": "usb_devices",
        "name": "USB & External Storage",
        "category": "Hardware & Devices",
        "icon": "usb",
        "description": "Reconstructs USB device connection history, vendor/product IDs, serial numbers, drive letters, and volume GUIDs.",
        "live_paths": [
            "REGISTRY:HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
            "REGISTRY:HKLM\\SYSTEM\\MountedDevices",
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"INF\setupapi.dev.log")
        ],
        "file_patterns": ["setupapi.dev.log", "system"],
        "folder_patterns": ["inf", "system32\\config"],
        "requires_admin": False,
    },
    {
        "id": "bam_dam",
        "name": "BAM / DAM (Background Activity Moderator)",
        "category": "Program Execution",
        "icon": "cpu",
        "description": "Kernel-level execution tracking of full paths and timestamps of executables executed per user SID.",
        "live_paths": ["REGISTRY:HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"],
        "file_patterns": ["system"],
        "folder_patterns": ["system32\\config"],
        "requires_admin": True,
    },
    {
        "id": "startup_persistence",
        "name": "Startup & Autorun Persistence",
        "category": "Persistence",
        "icon": "refresh-cw",
        "description": "Audits Run, RunOnce, StartupApproved registry keys and Startup folders for persistent malware entries.",
        "live_paths": [
            "REGISTRY:HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "REGISTRY:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
        ],
        "file_patterns": ["software", "ntuser.dat"],
        "folder_patterns": ["startup"],
        "requires_admin": False,
    },
    {
        "id": "event_logs",
        "name": "Windows Event Logs (EVTX)",
        "category": "Security & Logs",
        "icon": "shield",
        "description": "Analyzes critical security events (Logon 4624/4625, Process Creation 4688, Log Clearing 1102, Service 7045).",
        "live_paths": [
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\Winevt\Logs\Security.evtx"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\Winevt\Logs\System.evtx"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx"),
            os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), r"System32\Winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx"),
        ],
        "file_patterns": ["*.evtx"],
        "folder_patterns": ["winevt\\logs", "logs"],
        "requires_admin": True,
    },
    {
        "id": "jump_lists",
        "name": "Jump Lists",
        "category": "File Access",
        "icon": "list",
        "description": "Extracts recently opened documents and files associated with specific taskbar applications.",
        "live_paths": [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent\AutomaticDestinations"),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Recent\CustomDestinations"),
        ],
        "file_patterns": ["*.automaticdestinations-ms", "*.customdestinations-ms"],
        "folder_patterns": ["automaticdestinations", "customdestinations"],
        "requires_admin": False,
    }
]

def get_catalog() -> List[Dict[str, Any]]:
    """Returns full catalog of supported artifacts."""
    return ARTIFACT_CATALOG

def get_catalog_by_id(artifact_id: str) -> Optional[Dict[str, Any]]:
    """Returns catalog item for a specific artifact ID."""
    for item in ARTIFACT_CATALOG:
        if item["id"].lower() == artifact_id.lower():
            return item
    return None

def get_presets() -> List[Dict[str, Any]]:
    """Returns friendly categorized presets for UI dropdowns and CLI selectors."""
    presets = [
        {
            "id": "all_triage",
            "name": "⚡ Full Live Triage (All Artifacts)",
            "description": "Extracts and correlates all available execution, file access, web, USB, and security artifacts.",
            "category": "Comprehensive"
        },
        {
            "id": "execution_persistence",
            "name": "🚀 Program Execution & Persistence",
            "description": "Prefetch, UserAssist, BAM/DAM, and Startup Run keys.",
            "category": "Execution"
        },
        {
            "id": "file_access",
            "name": "📂 File Access & Explorer Activity",
            "description": "LNK Shortcut files, ShellBags, Jump Lists, and Recycle Bin.",
            "category": "File Access"
        },
        {
            "id": "browser_downloads",
            "name": "🌐 Web Browsers & Download History",
            "description": "Chrome, Edge, Brave, Opera, and Firefox browsing and download activity.",
            "category": "Web"
        },
        {
            "id": "powershell_cli",
            "name": "💻 PowerShell & Command Line History",
            "description": "ConsoleHost_history.txt with automated threat syntax heuristics.",
            "category": "Command Line"
        },
        {
            "id": "usb_storage",
            "name": "🔌 USB & External Devices",
            "description": "USBSTOR registry, MountedDevices volume IDs, and drive letter tracking.",
            "category": "Hardware"
        },
        {
            "id": "event_logs",
            "name": "🛡️ Security & Windows Event Logs",
            "description": "EVTX Logons (4624/4625), Process creation (4688), and Log tampering (1102).",
            "category": "Logs"
        }
    ]
    return presets

def discover_live_artifacts() -> Dict[str, List[str]]:
    """
    Discovers all available artifacts on the current live Windows machine.
    Returns mapping of artifact_id -> list of found existing paths or registry keys.
    """
    discovered = {}
    for item in ARTIFACT_CATALOG:
        art_id = item["id"]
        valid_paths = []
        for p in item["live_paths"]:
            if p.startswith("REGISTRY:"):
                # Registry keys are handled directly by their respective parsers
                valid_paths.append(p)
            elif os.path.exists(p):
                valid_paths.append(p)
            elif "*" in p:
                matches = glob.glob(p)
                if matches:
                    valid_paths.extend(matches)
        if valid_paths:
            discovered[art_id] = valid_paths
    return discovered

def scan_target_directory(target_dir: str) -> Dict[str, List[str]]:
    r"""
    Recursively scans an arbitrary folder (e.g. mounted drive E:\, forensic triage folder,
    KAPE output, or forensic dump) and classifies found files by artifact type.
    """
    results = {item["id"]: [] for item in ARTIFACT_CATALOG}
    if not os.path.isdir(target_dir):
        return results

    for root, dirs, files in os.walk(target_dir):
        root_lower = root.lower()
        for f in files:
            file_lower = f.lower()
            full_path = os.path.join(root, f)

            # Prefetch
            if file_lower.endswith(".pf") or "prefetch" in root_lower:
                if file_lower.endswith(".pf"):
                    results["prefetch"].append(full_path)

            # LNK Shortcut
            elif file_lower.endswith(".lnk"):
                results["lnk"].append(full_path)

            # Recycle Bin
            elif (file_lower.startswith("$i") or file_lower.startswith("i")) and ("$recycle.bin" in root_lower or "recycle.bin" in root_lower):
                results["recycle_bin"].append(full_path)

            # PowerShell History
            elif file_lower == "consolehost_history.txt" or ("psreadline" in root_lower and file_lower.endswith(".txt")):
                results["powershell_history"].append(full_path)

            # Web Browser History
            elif file_lower == "history" and any(b in root_lower for b in ["chrome", "edge", "brave", "opera", "user data"]):
                results["browser_history"].append(full_path)
            elif file_lower in ["places.sqlite", "downloads.sqlite"] or ("firefox" in root_lower and file_lower.endswith(".sqlite")):
                results["browser_history"].append(full_path)

            # Jump Lists
            elif file_lower.endswith(".automaticdestinations-ms") or file_lower.endswith(".customdestinations-ms"):
                results["jump_lists"].append(full_path)

            # Event Logs
            elif file_lower.endswith(".evtx") or "winevt" in root_lower:
                if file_lower.endswith(".evtx"):
                    results["event_logs"].append(full_path)

            # SetupAPI Dev Log (USB)
            elif file_lower == "setupapi.dev.log" or file_lower == "setupapi.setup.log":
                results["usb_devices"].append(full_path)

    # Remove empty lists
    return {k: v for k, v in results.items() if v}
