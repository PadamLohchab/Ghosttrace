"""
SPECTR — Artifact Extractor
Reads parsed image data and extracts forensic artifacts.
Works on actual mounted images or raw file paths.
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import Optional
from config import IOC_PATTERNS


class ArtifactExtractor:
    """
    Extracts forensic artifacts from evidence files.
    Handles: logs, registry exports, prefetch, browser history, raw text.
    """

    def __init__(self, evidence_path: str | Path):
        self.path     = Path(evidence_path)
        self.content  = ""
        self.artifacts = {
            "files":      [],
            "iocs":       [],
            "events":     [],
            "registry":   [],
            "usb_devices":[],
            "processes":  [],
            "timestamps": [],
            "raw_text":   "",
        }

    def load(self) -> bool:
        """Load evidence file content."""
        try:
            with open(self.path, "r", errors="replace") as f:
                self.content = f.read()
            self.artifacts["raw_text"] = self.content[:50000]  # cap for AI
            return True
        except Exception as e:
            print(f"[Extractor] Failed to load {self.path}: {e}")
            return False

    def extract_all(self) -> dict:
        """Run all extraction passes."""
        self.extract_iocs()
        self.extract_timestamps()
        self.extract_usb()
        self.extract_processes()
        return self.artifacts

    def extract_iocs(self) -> list:
        """Extract all IOC types using regex."""
        found = []
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = re.findall(pattern, self.content, re.IGNORECASE)
            for match in set(matches):
                # filter out localhost and obviously benign
                if ioc_type == "ip" and match.startswith(("127.", "0.", "255.")):
                    continue
                found.append({
                    "type":    ioc_type.upper(),
                    "value":   match,
                    "source":  self.path.name,
                    "severity":"MEDIUM",
                })
        self.artifacts["iocs"] = found
        return found

    def extract_timestamps(self) -> list:
        """Extract all timestamps from content."""
        patterns = [
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
            r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
            r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
        ]
        found = []
        for p in patterns:
            found.extend(re.findall(p, self.content))
        self.artifacts["timestamps"] = list(set(found))
        return self.artifacts["timestamps"]

    def extract_usb(self) -> list:
        """Extract USB device references."""
        usb_pattern = r"USBSTOR[\\\/][^\s\"'\n]+"
        matches = re.findall(usb_pattern, self.content, re.IGNORECASE)
        self.artifacts["usb_devices"] = list(set(matches))
        return self.artifacts["usb_devices"]

    def extract_processes(self) -> list:
        """Extract process/executable names."""
        exe_pattern = r"\b[\w\-]+\.exe\b"
        matches = re.findall(exe_pattern, self.content, re.IGNORECASE)
        # filter common benign processes
        benign = {"svchost.exe", "explorer.exe", "csrss.exe", "winlogon.exe"}
        suspicious = [m for m in set(matches) if m.lower() not in benign]
        self.artifacts["processes"] = suspicious
        return suspicious
