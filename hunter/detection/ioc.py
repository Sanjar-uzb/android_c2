import ipaddress
from pathlib import Path
from urllib.parse import urlparse


def _normalize(value: str) -> str:
    return (value or "").strip().strip("./").lower()


def _suffix_match(value: str, pattern: str) -> bool:
    value_norm = _normalize(value)
    pattern_norm = _normalize(pattern).lstrip("*.")
    if not value_norm or not pattern_norm:
        return False
    if value_norm == pattern_norm:
        return True
    if value_norm.endswith("." + pattern_norm):
        return True
    if pattern_norm.startswith("*."):
        base = pattern_norm[2:]
        return value_norm == base or value_norm.endswith("." + base)
    return False


def ioc_matches(value: str | None, iocs: set[str] | None) -> bool:
    if not value or not iocs:
        return False
    candidates = {str(item).strip() for item in iocs if str(item).strip()}
    if not candidates:
        return False

    value_norm = _normalize(value)
    if value_norm in {"", "."}:
        return False

    for item in candidates:
        item_norm = _normalize(item)
        if not item_norm:
            continue
        if value_norm == item_norm:
            return True
        try:
            if ipaddress.ip_address(value_norm) == ipaddress.ip_address(item_norm):
                return True
        except ValueError:
            pass
        if item_norm.startswith("*.") and _suffix_match(value_norm, item_norm):
            return True
        if value_norm.endswith("." + item_norm) or value_norm.startswith(item_norm + ":"):
            return True

    host = value_norm
    try:
        host = urlparse(value_norm).hostname or host
    except Exception:
        pass
    for item in candidates:
        item_norm = _normalize(item)
        if item_norm.startswith("http://") or item_norm.startswith("https://"):
            continue
        if host == item_norm or host.endswith("." + item_norm):
            return True
    return False


def load_ioc_file(path: str | Path | None):
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        return set()
    items = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            items.add(value.split()[0])
    return items


def load_ioc_sets(base_dir: str | Path):
    base = Path(base_dir)
    return {
        "ips": load_ioc_file(base / "ips.txt"),
        "domains": load_ioc_file(base / "domains.txt"),
        "urls": load_ioc_file(base / "urls.txt"),
        "hashes": load_ioc_file(base / "hashes.txt"),
    }
