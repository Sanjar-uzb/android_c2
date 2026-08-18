import re
from pathlib import Path

from hunter.filesystem import sha256_file


def extract_static_apk_info(apk_path: str | Path, iocs: set[str] | None = None):
    apk_path = Path(apk_path)
    digest = sha256_file(apk_path)
    rc, output, _ = __import__("subprocess").run(["strings", "-a", str(apk_path)], capture_output=True, text=True, timeout=60)
    if rc != 0:
        output = ""
    ips = sorted({x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output) if __import__("ipaddress").ip_address(x)})
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', output)))
    domains = sorted(set(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", output)))
    return {
        "apk": str(apk_path),
        "sha256": digest,
        "ipv4": ips,
        "urls": urls[:10000],
        "domains": domains[:10000],
        "ioc_ip_matches": sorted(set(ips) & (iocs or set())),
    }
