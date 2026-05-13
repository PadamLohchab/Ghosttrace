"""
SPECTR — Chain of Custody
Every action on evidence is logged here.
This log is immutable — entries are only appended, never edited.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class CustodyLog:
    """
    Maintains an append-only chain of custody log.
    Every evidence action is recorded with timestamp, analyst, and hash.
    """

    def __init__(self, case_id: str, log_path: Optional[Path] = None):
        self.case_id  = case_id
        self.entries  = []
        self.log_path = log_path

        if log_path and log_path.exists():
            self._load()

    def log(
        self,
        action:   str,
        analyst:  str,
        evidence: str,
        notes:    str = "",
        hashes:   Optional[dict] = None,
    ) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "case_id":   self.case_id,
            "action":    action,
            "analyst":   analyst,
            "evidence":  evidence,
            "notes":     notes,
            "hashes":    hashes or {},
        }
        self.entries.append(entry)
        if self.log_path:
            self._save()
        return entry

    def all_entries(self) -> list[dict]:
        return list(self.entries)

    def export_text(self) -> str:
        lines = [f"CHAIN OF CUSTODY — CASE {self.case_id}", "=" * 60]
        for e in self.entries:
            lines.append(f"\n[{e['timestamp']}]")
            lines.append(f"  Action:   {e['action']}")
            lines.append(f"  Analyst:  {e['analyst']}")
            lines.append(f"  Evidence: {e['evidence']}")
            if e["notes"]:
                lines.append(f"  Notes:    {e['notes']}")
            if e["hashes"]:
                for alg, val in e["hashes"].items():
                    lines.append(f"  {alg.upper()}: {val}")
        return "\n".join(lines)

    def _save(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "w") as f:
            json.dump(self.entries, f, indent=2)

    def _load(self):
        with open(self.log_path) as f:
            self.entries = json.load(f)
