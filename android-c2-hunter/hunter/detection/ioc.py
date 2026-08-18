from pathlib import Path


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
