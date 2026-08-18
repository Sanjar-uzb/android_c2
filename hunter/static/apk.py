import re
from pathlib import Path

from hunter.filesystem import sha256_file
from hunter.static.manifest import extract_manifest
from hunter.static.dex import extract_dex_metadata


def extract_static_apk_info(apk_path: str | Path, iocs: set[str] | None = None):
    apk_path = Path(apk_path)
    digest = sha256_file(apk_path)
    
    # String-based extraction (legacy)
    rc, output, _ = __import__("subprocess").run(["strings", "-a", str(apk_path)], capture_output=True, text=True, timeout=60)
    if rc != 0:
        output = ""
    
    ips = sorted({x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output) if __import__("ipaddress").ip_address(x)})
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', output)))
    domains = sorted(set(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", output)))
    
    # Manifest analysis
    manifest_result = extract_manifest(apk_path)
    
    # DEX analysis
    dex_result = extract_dex_metadata(apk_path)
    
    static_score = 0
    if manifest_result.get("c2_score"):
        static_score += manifest_result["c2_score"]
    if dex_result.get("c2_score"):
        static_score += dex_result["c2_score"]
    if ips:
        static_score += min(len(ips), 10)
    if urls:
        static_score += min(len(urls), 20)
    
    return {
        "apk": str(apk_path),
        "sha256": digest,
        "ipv4": ips[:100],
        "urls": urls[:100],
        "domains": domains[:100],
        "ioc_ip_matches": sorted(set(ips) & (iocs or set())),
        "manifest": manifest_result.get("manifest", {}),
        "manifest_score": manifest_result.get("c2_score", 0),
        "dex_count": dex_result.get("dex_count", 0),
        "dex_indicators": {k: v for k, v in dex_result.items() if isinstance(v, list)},
        "dex_score": dex_result.get("c2_score", 0),
        "static_c2_score": static_score,
    }
