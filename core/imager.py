"""
GhostTrace — Forensic Image Acquirer
Handles acquisition of forensic disk/memory images from physical devices.

NOTE: Physical acquisition requires:
  - A hardware write-blocker connected to the source drive
  - pytsk3 library (optional — complex to install on Windows)
  - Administrative / root privileges

This module provides a safe software-level copy as a fallback
when pytsk3 is not available.
"""

import os
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Callable
from utils.logger import get_logger

log = get_logger("imager")

# Attempt to import pytsk3 (optional)
try:
    import pytsk3
    HAS_TSK = True
except ImportError:
    HAS_TSK = False
    log.warning("[Imager] pytsk3 not installed — disk-level imaging unavailable. "
                "Using software-level copy only.")


class ForensicImager:
    """
    Creates forensic copies of evidence files / disk images.
    Computes hashes during copying to ensure integrity.
    Never writes to source devices — always read-only.
    """

    def __init__(self, output_dir: Optional[Path] = None):
        from config import CASES_DIR
        self.output_dir = output_dir or CASES_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def acquire_file(
        self,
        source_path: str,
        dest_name:   Optional[str] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
    ) -> dict:
        """
        Copy a file and compute MD5 + SHA256 simultaneously.

        Args:
            source_path: Path to source evidence file.
            dest_name:   Output filename (auto-generated if None).
            progress_cb: Optional callback(percent: int).

        Returns:
            dict with: dest_path, md5, sha256, size, size_str, acquired_at
        """
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source not found: {source_path}")

        dest_name = dest_name or f"{source.stem}_forensic_{datetime.now().strftime('%Y%m%d_%H%M%S')}{source.suffix}"
        dest      = self.output_dir / dest_name

        md5_h    = hashlib.md5()
        sha256_h = hashlib.sha256()
        size     = source.stat().st_size
        done     = 0
        chunk    = 65536

        log.info(f"[Imager] Acquiring {source} → {dest}  ({size:,} bytes)")

        with open(source, "rb") as src, open(dest, "wb") as dst:
            while data := src.read(chunk):
                dst.write(data)
                md5_h.update(data)
                sha256_h.update(data)
                done += len(data)
                if progress_cb and size > 0:
                    progress_cb(int(done / size * 100))

        result = {
            "source":      str(source),
            "dest_path":   str(dest),
            "md5":         md5_h.hexdigest(),
            "sha256":      sha256_h.hexdigest(),
            "size":        size,
            "size_str":    _fmt_size(size),
            "acquired_at": datetime.now(timezone.utc).isoformat(),
        }
        log.info(f"[Imager] Done. SHA256: {result['sha256'][:16]}...")
        return result

    def verify(self, file_path: str, known_md5: str = "", known_sha256: str = "") -> bool:
        """
        Verify a file against known hashes.
        Returns True if both provided hashes match.
        """
        md5_h    = hashlib.md5()
        sha256_h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                md5_h.update(chunk)
                sha256_h.update(chunk)

        md5_ok    = (not known_md5    or md5_h.hexdigest().lower()    == known_md5.lower())
        sha256_ok = (not known_sha256 or sha256_h.hexdigest().lower() == known_sha256.lower())
        return md5_ok and sha256_ok

    @staticmethod
    def has_tsk_support() -> bool:
        """Returns True if pytsk3 is installed (enables raw disk image parsing)."""
        return HAS_TSK


def _fmt_size(b: int) -> str:
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"
