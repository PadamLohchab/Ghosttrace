"""
GhostTrace — Forensic Image Parser
Parses disk images and forensic containers to enumerate files and filesystems.

Requires pytsk3 for raw disk images (optional on Windows).
Falls back to direct file enumeration for log/text artifacts.
"""

import os
from pathlib import Path
from typing import Optional, List
from utils.logger import get_logger

log = get_logger("parser")

try:
    import pytsk3
    HAS_TSK = True
except ImportError:
    HAS_TSK = False
    log.warning("[Parser] pytsk3 not available — disk image parsing disabled.")

SUPPORTED_FORMATS = [".dd", ".img", ".raw", ".e01", ".vmdk", ".vhd", ".vmem", ".dmp"]


class ImageParser:
    """
    Parses forensic disk images to list files and extract content.

    When pytsk3 is unavailable, falls back to treating the image
    as a binary blob and extracting printable strings.
    """

    def __init__(self, image_path: str):
        self.image_path = Path(image_path)
        self.files:     List[dict] = []
        self._img_info  = None
        self._fs_info   = None

    def open(self) -> bool:
        """
        Open the image for parsing.
        Returns True if successfully opened.
        """
        if not self.image_path.exists():
            log.error(f"[Parser] Image not found: {self.image_path}")
            return False

        ext = self.image_path.suffix.lower()

        if HAS_TSK and ext in SUPPORTED_FORMATS:
            return self._open_tsk()
        else:
            log.info(f"[Parser] Using fallback string extraction for {self.image_path.name}")
            return True  # Fallback mode — always succeeds

    def _open_tsk(self) -> bool:
        """Open via pytsk3."""
        try:
            self._img_info = pytsk3.Img_Info(str(self.image_path))
            self._fs_info  = pytsk3.FS_Info(self._img_info)
            log.info(f"[Parser] Opened disk image: {self.image_path.name}")
            return True
        except Exception as e:
            log.error(f"[Parser] pytsk3 failed: {e}")
            return False

    def list_files(self, max_files: int = 1000) -> List[dict]:
        """
        Enumerate files in the image.
        Returns list of {name, path, size, inode, type} dicts.
        """
        if self._fs_info:
            return self._list_tsk(max_files)
        return []  # Binary blob — cannot enumerate files

    def _list_tsk(self, max_files: int) -> List[dict]:
        """Enumerate files using pytsk3."""
        files   = []
        counter = [0]

        def _walk(directory, path="/"):
            if counter[0] >= max_files:
                return
            for entry in directory:
                if not hasattr(entry, "info"):
                    continue
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                full_path = f"{path}{name}"
                meta = entry.info.meta
                size = meta.size if meta else 0
                files.append({"name": name, "path": full_path, "size": size, "type": "file"})
                counter[0] += 1
                try:
                    if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        sub_dir = entry.as_directory()
                        _walk(sub_dir, full_path + "/")
                except Exception:
                    pass

        try:
            root = self._fs_info.open_dir(path="/")
            _walk(root)
        except Exception as e:
            log.warning(f"[Parser] File enumeration error: {e}")

        self.files = files
        return files

    def extract_strings(self, min_length: int = 6, max_bytes: int = 500_000) -> str:
        """
        Extract printable ASCII strings from raw image bytes.
        Useful as a fallback when filesystem parsing is not available.
        """
        try:
            with open(self.image_path, "rb") as f:
                data = f.read(max_bytes)
            strings = []
            current = bytearray()
            for byte in data:
                if 32 <= byte < 127:
                    current.append(byte)
                else:
                    if len(current) >= min_length:
                        strings.append(current.decode("ascii"))
                    current = bytearray()
            return "\n".join(strings)
        except Exception as e:
            log.error(f"[Parser] String extraction failed: {e}")
            return ""

    def close(self):
        self._img_info = None
        self._fs_info  = None
