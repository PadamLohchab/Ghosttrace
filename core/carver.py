"""
GhostTrace — File Carver
Recovers deleted files and carves files from raw disk images by file signatures.

Signature-based carving works on raw (.dd/.img/.raw) images.
Does NOT require pytsk3 — reads raw bytes directly.
"""

import os
import struct
from pathlib import Path
from typing import Optional, List
from utils.logger import get_logger

log = get_logger("carver")

# File signatures (magic bytes): {ext: (header_bytes, footer_bytes, max_size)}
FILE_SIGNATURES = {
    "jpg":  (b"\xFF\xD8\xFF",          b"\xFF\xD9",         10_000_000),
    "pdf":  (b"%PDF",                  b"%%EOF",            50_000_000),
    "png":  (b"\x89PNG\r\n\x1a\n",    b"\x49\x45\x4E\x44\xAE\x42\x60\x82", 10_000_000),
    "zip":  (b"PK\x03\x04",           b"PK\x05\x06",       100_000_000),
    "doc":  (b"\xD0\xCF\x11\xE0",     b"",                  50_000_000),
    "docx": (b"PK\x03\x04",           b"",                  50_000_000),
    "exe":  (b"MZ",                    b"",                  50_000_000),
    "mp4":  (b"\x00\x00\x00\x18\x66\x74\x79\x70", b"",    500_000_000),
    "sqlite": (b"SQLite format 3\x00", b"",                 500_000_000),
}


class FileCarver:
    """
    Carves files from raw disk images using header/footer signatures.
    Works on .dd, .img, .raw, and any binary file.
    """

    def __init__(self, image_path: str, output_dir: Optional[str] = None):
        self.image_path = Path(image_path)
        self.output_dir = Path(output_dir) if output_dir else (
            Path(image_path).parent / f"carved_{Path(image_path).stem}"
        )
        self.carved: List[dict] = []

    def carve(
        self,
        file_types: Optional[List[str]] = None,
        max_files:  int = 200,
        chunk_size: int = 10_000_000,
        progress_cb=None,
    ) -> List[dict]:
        """
        Carve files from the image.

        Args:
            file_types: List of extensions to recover, e.g. ['jpg','pdf'].
                        None = all supported types.
            max_files:  Stop after recovering this many files.
            chunk_size: Bytes to read per chunk (default 10 MB).
            progress_cb: Optional callback(percent: int).

        Returns:
            List of {path, ext, offset, size} dicts for carved files.
        """
        if not self.image_path.exists():
            log.error(f"[Carver] Image not found: {self.image_path}")
            return []

        self.output_dir.mkdir(parents=True, exist_ok=True)
        sigs    = {k: v for k, v in FILE_SIGNATURES.items()
                   if file_types is None or k in file_types}
        total   = self.image_path.stat().st_size
        offset  = 0
        count   = 0
        buffer  = b""

        log.info(f"[Carver] Starting carve of {self.image_path.name} "
                 f"({total:,} bytes, {list(sigs.keys())} types)")

        with open(self.image_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buffer += chunk

                for ext, (header, footer, max_sz) in sigs.items():
                    pos = 0
                    while (start := buffer.find(header, pos)) != -1:
                        if footer:
                            end = buffer.find(footer, start + len(header))
                            if end == -1:
                                break
                            end += len(footer)
                        else:
                            end = min(start + max_sz, len(buffer))

                        file_data = buffer[start:end]
                        if len(file_data) > 50:  # Skip tiny fragments
                            carved_path = self.output_dir / f"carved_{count:04d}.{ext}"
                            carved_path.write_bytes(file_data)
                            self.carved.append({
                                "path":   str(carved_path),
                                "ext":    ext,
                                "offset": offset + start,
                                "size":   len(file_data),
                            })
                            count += 1
                            log.info(f"[Carver] Recovered {ext}: {carved_path.name} "
                                     f"({len(file_data):,} bytes)")

                        pos = start + 1
                        if count >= max_files:
                            log.info(f"[Carver] Reached max_files limit ({max_files})")
                            return self.carved

                # Keep last 1 MB for overlap detection across chunks
                buffer = buffer[-1_000_000:] if len(buffer) > 1_000_000 else buffer
                offset += len(chunk)

                if progress_cb and total > 0:
                    progress_cb(int(offset / total * 100))

        log.info(f"[Carver] Carve complete — {len(self.carved)} files recovered")
        return self.carved

    def get_summary(self) -> str:
        if not self.carved:
            return "No files carved."
        by_type = {}
        for f in self.carved:
            by_type[f["ext"]] = by_type.get(f["ext"], 0) + 1
        parts = [f"{ext}: {n}" for ext, n in by_type.items()]
        return f"Recovered {len(self.carved)} files — {', '.join(parts)}"
