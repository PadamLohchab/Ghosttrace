"""
SPECTR — Hasher
Computes MD5, SHA1, SHA256 for evidence integrity
"""

import hashlib
from pathlib import Path
from typing import Optional
from config import HASH_CHUNK_SIZE


class Hasher:
    """
    Computes cryptographic hashes of files in chunks.
    Never loads entire file into memory — safe for large disk images.
    """

    @staticmethod
    def compute(file_path: str | Path, algorithms: list[str] = None) -> dict:
        """
        Compute hashes for a file.
        Returns dict: {algorithm: hex_digest}
        """
        if algorithms is None:
            algorithms = ["md5", "sha1", "sha256"]

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        hashers = {alg: hashlib.new(alg) for alg in algorithms}

        with open(path, "rb") as f:
            while chunk := f.read(HASH_CHUNK_SIZE):
                for h in hashers.values():
                    h.update(chunk)

        return {alg: h.hexdigest() for alg, h in hashers.items()}

    @staticmethod
    def verify(file_path: str | Path, known_hashes: dict) -> dict:
        """
        Verify file against known good hashes.
        Returns dict: {algorithm: True/False}
        """
        computed = Hasher.compute(file_path, list(known_hashes.keys()))
        return {
            alg: computed.get(alg, "").lower() == known.lower()
            for alg, known in known_hashes.items()
        }

    @staticmethod
    def hash_string(content: str, algorithm: str = "sha256") -> str:
        """Hash a string directly — for content integrity."""
        return hashlib.new(algorithm, content.encode()).hexdigest()
