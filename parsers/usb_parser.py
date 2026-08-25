# parsers/usb_parser.py
r"""
USB & Removable Storage Forensics Parser.
Extracts:
- USBSTOR device enumeration (Vendor, Product ID, Serial Number, Firmware revision)
- MountedDevices (Drive letters assigned to USB devices, Volume GUIDs)
- Timestamps: Device connection history, last write times
- setupapi.dev.log device installation timestamps
"""

import os
import re
import datetime
from typing import List, Dict, Any, Optional

from utils import normalize_timestamp

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

def _regtime_to_iso(raw_time: Optional[int]) -> Optional[str]:
    if raw_time is None or raw_time <= 0:
        return None
    try:
        if raw_time > 10**12:
            microseconds = raw_time / 10.0
            epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            dt = epoch + datetime.timedelta(microseconds=microseconds)
        else:
            dt = datetime.datetime.fromtimestamp(raw_time, tz=datetime.timezone.utc)
        return normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
    except Exception:
        return None

def parse_live_usbstor() -> List[Dict[str, Any]]:
    r"""
    Parses HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR and HKLM\SYSTEM\MountedDevices.
    """
    records = []
    if not HAS_WINREG:
        return records

    # 1. Fetch Drive Letter mappings from MountedDevices
    drive_mappings = {}  # serial_or_guid -> drive letter
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as md_key:
            _, val_count, _ = winreg.QueryInfoKey(md_key)
            for i in range(val_count):
                try:
                    val_name, val_data, _ = winreg.EnumValue(md_key, i)
                    if isinstance(val_data, (bytes, bytearray)):
                        try:
                            # Usually contains signature or UTF-16 device string
                            data_str = val_data.decode("utf-16le", errors="ignore")
                            if val_name.startswith(r"\DosDevices\\"):
                                drive_letter = val_name.replace(r"\DosDevices\\", "")
                                drive_mappings[data_str.lower()] = drive_letter
                        except Exception:
                            pass
                except Exception:
                    continue
    except Exception:
        pass

    # 2. Enumerate USBSTOR devices
    usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path) as usbstor_key:
            device_type_count, _, _ = winreg.QueryInfoKey(usbstor_key)
            for i in range(device_type_count):
                try:
                    device_type_name = winreg.EnumKey(usbstor_key, i)
                    dev_type_sub_path = f"{usbstor_path}\\{device_type_name}"

                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_type_sub_path) as dev_key:
                        serial_count, _, _ = winreg.QueryInfoKey(dev_key)
                        for j in range(serial_count):
                            try:
                                serial_name = winreg.EnumKey(dev_key, j)
                                serial_sub_path = f"{dev_type_sub_path}\\{serial_name}"

                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, serial_sub_path) as inst_key:
                                    key_info = winreg.QueryInfoKey(inst_key)
                                    last_write = _regtime_to_iso(key_info[2])

                                    # Try to read friendly name
                                    friendly_name = ""
                                    try:
                                        friendly_name, _ = winreg.QueryValueEx(inst_key, "FriendlyName")
                                    except Exception:
                                        pass

                                    # Try to find assigned drive letter
                                    assigned_drive = "N/A"
                                    serial_clean = serial_name.split("&")[0].lower()
                                    for mapped_data, drv in drive_mappings.items():
                                        if serial_clean in mapped_data:
                                            assigned_drive = drv
                                            break

                                    # Parse Device Descriptor (e.g. Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00)
                                    vendor = ""
                                    product = ""
                                    rev = ""
                                    m_ven = re.search(r"Ven_([^&]+)", device_type_name, re.I)
                                    m_prod = re.search(r"Prod_([^&]+)", device_type_name, re.I)
                                    m_rev = re.search(r"Rev_([^&]+)", device_type_name, re.I)
                                    if m_ven: vendor = m_ven.group(1).replace("_", " ")
                                    if m_prod: product = m_prod.group(1).replace("_", " ")
                                    if m_rev: rev = m_rev.group(1).replace("_", " ")

                                    display_name = friendly_name or f"{vendor} {product}".strip() or device_type_name

                                    extra_dict = {
                                        "source": "registry:usbstor",
                                        "vendor": vendor,
                                        "product": product,
                                        "revision": rev,
                                        "serial_number": serial_name,
                                        "assigned_drive": assigned_drive,
                                        "friendly_name": friendly_name
                                    }
                                    extra_str = ";".join(f"{k}={str(v).replace(';', ',')}" for k, v in extra_dict.items() if v is not None)

                                    records.append({
                                        "artifact_type": "usb_device",
                                        "name": display_name[:80],
                                        "path": f"USBSTOR\\{device_type_name}\\{serial_name}",
                                        "timestamp": last_write,
                                        "last_access": last_write,
                                        "extra": extra_str,
                                        "details": str({
                                            "device": display_name,
                                            "serial": serial_name,
                                            "drive": assigned_drive,
                                            "vendor": vendor,
                                            "product": product,
                                            "key_path": serial_sub_path
                                        })
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
    except Exception:
        pass

    return records

def parse_setupapi_log(log_path: str) -> List[Dict[str, Any]]:
    """
    Parses setupapi.dev.log for USB installation events.
    """
    records = []
    if not os.path.isfile(log_path):
        return records

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Match Device Install sections
        pattern = re.compile(
            r">>>\s+\[Device Install \(Hardware initiated\) - (USBSTOR\\[^\]]+)\]\s+>>>\s+Section start ([\d/:\. ]+)",
            re.I
        )
        for match in pattern.finditer(content):
            device_str = match.group(1)
            time_str = match.group(2)

            ts = None
            try:
                # E.g. "2024/02/10 14:22:01.123"
                dt = datetime.datetime.strptime(time_str.split(".")[0].strip(), "%Y/%m/%d %H:%M:%S")
                dt = dt.replace(tzinfo=datetime.timezone.utc)
                ts = normalize_timestamp(dt.isoformat().replace("+00:00", "Z"))
            except Exception:
                ts = None

            records.append({
                "artifact_type": "usb_install",
                "name": os.path.basename(device_str),
                "path": device_str,
                "timestamp": ts,
                "last_access": None,
                "extra": f"source=setupapi.dev.log;device_id={device_str}",
                "details": str({"device": device_str, "install_time": time_str})
            })
    except Exception:
        pass

    return records
