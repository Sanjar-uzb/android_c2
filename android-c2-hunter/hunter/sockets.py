import ipaddress
import socket
from typing import Any, Dict, List

from hunter.adb import adb_shell
from hunter.packages import uid_packages
from hunter.processes import pid_inodes

STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def _hex_to_ip(value: str) -> str | None:
    try:
        return socket.inet_ntoa(bytes.fromhex(value)[::-1])
    except Exception:
        return None


def _hex_to_ipv6(value: str) -> str | None:
    try:
        return str(ipaddress.IPv6Address(bytes.fromhex(value)))
    except Exception:
        return None


def parse_proc_net(text: str, proto: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    decoder = _hex_to_ipv6 if proto.endswith("6") else _hex_to_ip
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('sl'):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local, remote, state = parts[1], parts[2], parts[3]
            uid = 'unknown'
            inode = 'unknown'
            if len(parts) >= 10:
                uid = parts[7]
                inode = parts[9]
            elif len(parts) >= 5:
                uid = parts[4] if parts[4].isdigit() else uid
                inode = parts[-1] if parts[-1].isdigit() else inode
            lip, lp = local.rsplit(":", 1)
            rip, rp = remote.rsplit(":", 1)
            rows.append({
                "proto": proto,
                "local_ip": decoder(lip),
                "local_port": int(lp, 16),
                "remote_ip": decoder(rip),
                "remote_port": int(rp, 16),
                "state_hex": state,
                "state": STATES.get(state, state) if proto.startswith("tcp") else "UDP",
                "uid": uid,
                "inode": inode,
            })
        except Exception:
            continue
    return rows


def enrich_socket_metadata(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    package_map = uid_packages()
    pid_map = pid_inodes()
    enriched: List[Dict[str, Any]] = []
    for row in rows:
        inode = str(row.get("inode", ""))
        uid = str(row.get("uid", ""))
        pids = sorted(pid_map.get(inode, set()))
        packages = package_map.get(uid, [])
        row["pids"] = pids
        row["packages"] = packages
        row["package"] = packages[0] if packages else ""
        row["pid"] = pids[0] if pids else ""
        enriched.append(row)
    return enriched


def get_android_sockets(package: str = "") -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        rc, out, _ = adb_shell(f"cat /proc/net/{proto}", timeout=10)
        if rc == 0:
            result.extend(parse_proc_net(out, proto))
    result = enrich_socket_metadata(result)
    if package:
        package_norm = package.lower()
        result = [row for row in result if any(pkg.lower() == package_norm for pkg in row.get("packages", [])) or (row.get("package") and row.get("package").lower() == package_norm)]
    return result
