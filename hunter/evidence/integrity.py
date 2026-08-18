import hashlib
from pathlib import Path


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_integrity_marker(path: str | Path, payload: str):
    target = Path(path)
    target.write_text(payload + "\n" + sha256_text(payload) + "\n", encoding="utf-8")
    return str(target)
