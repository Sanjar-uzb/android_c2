import ipaddress
import re
import subprocess
from pathlib import Path

from hunter.filesystem import sha256_file
from hunter.static.manifest import extract_manifest
from hunter.static.dex import extract_dex_metadata


IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

URL_RE = re.compile(
    r'https?://[^\s"\'<>]+',
    re.IGNORECASE,
)

DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b"
)


def extract_ipv4(text: str) -> list[str]:
    """Extract valid IPv4 addresses from text."""
    result = set()

    for value in IPV4_RE.findall(text):
        try:
            ip = ipaddress.ip_address(value)

            if ip.version == 4:
                result.add(str(ip))

        except ValueError:
            continue

    return sorted(result)


def extract_static_apk_info(
    apk_path: str | Path,
    iocs: set[str] | None = None,
):
    apk_path = Path(apk_path)

    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    digest = sha256_file(apk_path)

    # ---------------------------------------------------------
    # String extraction
    # ---------------------------------------------------------
    proc = subprocess.run(
        ["strings", "-a", str(apk_path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    output = proc.stdout if proc.returncode == 0 else ""

    # ---------------------------------------------------------
    # Network indicators
    # ---------------------------------------------------------
    ips = extract_ipv4(output)

    urls = sorted(
        set(URL_RE.findall(output))
    )

    domains = sorted(
        set(DOMAIN_RE.findall(output))
    )

    # Remove obvious APK/binary false positives.
    domains = [
        domain
        for domain in domains
        if not domain.lower().endswith(
            (
                ".xml",
                ".png",
                ".dex",
                ".apk",
                ".pk",
                ".sf",
                ".mf",
            )
        )
    ]

    # ---------------------------------------------------------
    # IOC matching
    # ---------------------------------------------------------
    ioc_set = iocs or set()

    ioc_ip_matches = sorted(
        set(ips) & ioc_set
    )

    ioc_domain_matches = sorted(
        set(domains) & ioc_set
    )

    ioc_url_matches = sorted(
        set(urls) & ioc_set
    )

    # ---------------------------------------------------------
    # AndroidManifest.xml analysis
    # ---------------------------------------------------------
    manifest_result = extract_manifest(apk_path)

    # ---------------------------------------------------------
    # DEX analysis
    # ---------------------------------------------------------
    dex_result = extract_dex_metadata(apk_path)

    # ---------------------------------------------------------
    # Static C2 score
    # ---------------------------------------------------------
    static_score = 0

    manifest_score = manifest_result.get("c2_score", 0)
    dex_score = dex_result.get("c2_score", 0)

    static_score += manifest_score
    static_score += dex_score

    if ips:
        static_score += min(len(ips), 10)

    if urls:
        static_score += min(len(urls), 20)

    if domains:
        static_score += min(len(domains), 10)

    if ioc_ip_matches:
        static_score += min(len(ioc_ip_matches) * 10, 30)

    if ioc_domain_matches:
        static_score += min(len(ioc_domain_matches) * 10, 30)

    return {
        "apk": str(apk_path),
        "sha256": digest,

        "ipv4": ips[:100],
        "urls": urls[:100],
        "domains": domains[:100],

        "ioc_ip_matches": ioc_ip_matches[:100],
        "ioc_domain_matches": ioc_domain_matches[:100],
        "ioc_url_matches": ioc_url_matches[:100],

        "manifest": manifest_result.get(
            "manifest",
            {},
        ),

        "manifest_score": manifest_score,

        "dex_count": dex_result.get(
            "dex_count",
            0,
        ),

        "dex_indicators": {
            key: value
            for key, value in dex_result.items()
            if isinstance(value, list)
        },

        "dex_score": dex_score,

        "static_c2_score": static_score,
    }