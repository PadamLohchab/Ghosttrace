"""
SPECTR — Helper Utilities
"""

from pathlib import Path
from datetime import datetime


def fmt_size(size_bytes: int) -> str:
    """Format bytes to human readable."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def fmt_ts(ts: str) -> str:
    """Format ISO timestamp to readable."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d  %H:%M:%S UTC")
    except Exception:
        return ts


def generate_case_id() -> str:
    """Generate a unique case ID."""
    return f"DF-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def safe_read(path: Path, max_bytes: int = 500_000) -> str:
    """Read file safely — limit size, handle encoding errors."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes)
    except Exception as e:
        return f"[Could not read file: {e}]"
