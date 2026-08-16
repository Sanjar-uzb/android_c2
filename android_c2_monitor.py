#!/usr/bin/env python3
"""
Android C2 Hunter - defensive APK/network triage tool.

Modes:
  static   Extract IPs/URLs/domains from an APK and match IOC IPs.
  monitor  Poll Android /proc socket tables over ADB and correlate socket
           inodes to PIDs when Android permissions allow it.
  capture  Capture host-visible traffic to a PCAP with tcpdump.
  report   Summarize dynamic JSONL evidence.

Use only on APKs/devices you are authorized to analyze.
"""

import argparse, hashlib, ipaddress, json, re, shutil, socket, subprocess, sys, time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

COMMON_PORTS = {53, 80, 123, 443, 8080, 8443, 5228, 5229, 5230}
SUSPICIOUS_PORTS = {4444, 5555, 1337, 31337, 12345, 6667}
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def now():
    return datetime.now(timezone.utc).isoformat()

def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def adb_shell(command, timeout=15):
    # command is generated locally; do not pass untrusted shell input here.
    return run("adb shell " + command, timeout)

def adb_devices():
    rc, out, _ = run("adb devices")
    if rc != 0:
        return []
    return [x.split()[0] for x in out.splitlines() if "\tdevice" in x]

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_private(ip):
    try:
        x = ipaddress.ip_address(ip)
        return any(x in n for n in PRIVATE_NETS)
    except ValueError:
        return False

def hex_to_ip(h):
    try:
        return socket.inet_ntoa(bytes.fromhex(h)[::-1])
    except Exception:
        return None

def parse_proc(content, proto):
    rows = []
    for line in content.splitlines()[1:]:
        p = line.split()
        if len(p) < 10:
            continue
        try:
            local, remote, state = p[1], p[2], p[3]
            inode = p[9]
            lip, lp = local.split(":")
            rip, rp = remote.split(":")
            rows.append({
                "proto": proto,
                "local_ip": hex_to_ip(lip),
                "local_port": int(lp, 16),
                "remote_ip": hex_to_ip(rip),
                "remote_port": int(rp, 16),
                "state": state,
                "inode": inode,
            })
        except Exception:
            continue
    return rows

def get_sockets():
    result = []
    for proto in ("tcp", "udp"):
        rc, out, _ = adb_shell(f"cat /proc/net/{proto}", 10)
        if rc == 0:
            result.extend(parse_proc(out, proto))
    return result

def get_pid_inodes():
    # Android may deny /proc/<pid>/fd access. That is handled gracefully.
    script = r"""for p in /proc/[0-9]*; do
pid=${p##*/}
for f in $p/fd/*; do
x=$(readlink "$f" 2>/dev/null)
case "$x" in socket:\[*\]) echo "$pid ${x#socket:[};";; esac
done
done"""
    rc, out, _ = adb_shell("sh -c " + repr(script), 30)
    mapping = defaultdict(set)
    if rc != 0:
        return mapping
    for line in out.splitlines():
        m = re.match(r"^(\d+)\s+(\d+)", line)
        if m:
            mapping[m.group(2)].add(m.group(1))
    return mapping

def pid_cmdline(pid):
    rc, out, _ = adb_shell(f"cat /proc/{pid}/cmdline", 5)
    return out.replace("\x00", " ").strip() if rc == 0 else ""

def score_connection(row, iocs):
    ip = row.get("remote_ip")
    port = row.get("remote_port", 0)
    score = 0
    reasons = []

    if ip in iocs:
        score += 100
        reasons.append("IOC_MATCH")
    if ip and is_private(ip):
        reasons.append("PRIVATE_IP")
    else:
        score += 1
    if port in SUSPICIOUS_PORTS:
        score += 5
        reasons.append("SUSPICIOUS_PORT")
    if port > 1024 and port not in COMMON_PORTS:
        score += 2
        reasons.append("UNCOMMON_REMOTE_PORT")
    if row.get("proto") == "udp" and port not in {53, 123}:
        score += 1
        reasons.append("NONSTANDARD_UDP")
    return score, reasons

def load_iocs(path):
    if not path:
        return set()
    p = Path(path)
    if not p.exists():
        print(f"[!] IOC file not found: {p}")
        return set()
    return {x.strip() for x in p.read_text(errors="ignore").splitlines()
            if x.strip() and not x.strip().startswith("#")}

def static_apk(apk, outdir, iocs):
    outdir.mkdir(parents=True, exist_ok=True)
    digest = sha256_file(apk)
    rc, strings, _ = run(f'strings -a "{apk}"', 30)

    ips = sorted({x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", strings) if is_ip(x)})
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', strings)))
    domains = sorted(set(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", strings)))

    result = {
        "timestamp": now(),
        "apk": str(apk),
        "sha256": digest,
        "ipv4": ips,
        "urls": urls[:5000],
        "domains": domains[:5000],
        "ioc_ipv4": [x for x in ips if x in iocs],
    }
    (outdir / "static_iocs.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"[+] SHA256: {digest}")
    print(f"[+] IPv4:   {len(ips)}")
    print(f"[+] URLs:   {len(urls)}")
    print(f"[+] Domains:{len(domains)}")
    if result["ioc_ipv4"]:
        print("[!!!] IOC IP MATCH:")
        for ip in result["ioc_ipv4"]:
            print("    " + ip)
    return result

def monitor(outdir, interval, duration, iocs):
    if not adb_devices():
        print("[-] No authorized ADB device. Run: adb devices")
        return 1

    outdir.mkdir(parents=True, exist_ok=True)
    print("[+] ADB device connected")
    print("[+] Monitoring /proc/net/tcp and /proc/net/udp")
    inode_map = get_pid_inodes()
    if not inode_map:
        print("[!] PID correlation unavailable; Android may restrict /proc/<pid>/fd.")
        print("[!] IP/port monitoring will continue.")

    seen = set()
    records = []
    started = time.time()

    try:
        while not duration or time.time() - started < duration:
            for s in get_sockets():
                rip = s["remote_ip"]
                if not rip or rip in ("0.0.0.0", "::"):
                    continue

                key = (s["proto"], s["local_ip"], s["local_port"],
                       rip, s["remote_port"], s["state"], s["inode"])
                if key in seen:
                    continue
                seen.add(key)

                pids = sorted(inode_map.get(s["inode"], []))
                processes = [pid_cmdline(pid) for pid in pids]
                processes = [x for x in processes if x]

                score, reasons = score_connection(s, iocs)
                rec = {
                    "timestamp": now(),
                    **s,
                    "pids": pids,
                    "processes": processes,
                    "score": score,
                    "reasons": reasons,
                    "ioc": rip in iocs,
                }
                records.append(rec)
                print(json.dumps(rec, ensure_ascii=False))

            (outdir / "dynamic.jsonl").write_text(
                "\n".join(json.dumps(x, ensure_ascii=False) for x in records) + "\n"
            )
            inode_map = get_pid_inodes()
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped.")

    return 0

def capture(outdir, interface, duration):
    if not shutil.which("tcpdump"):
        print("[-] tcpdump not installed.")
        return 1
    outdir.mkdir(parents=True, exist_ok=True)
    pcap = outdir / "traffic.pcap"
    cmd = f'sudo tcpdump -i "{interface}" -nn -U -w "{pcap}"'
    print("[+] " + cmd)
    p = subprocess.Popen(cmd, shell=True)
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    print(f"[+] PCAP saved: {pcap}")
    return 0

def report(outdir):
    f = outdir / "dynamic.jsonl"
    if not f.exists():
        print("[-] No dynamic.jsonl found.")
        return
    rows = [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
    by_ip = defaultdict(lambda: {"events": 0, "ports": set(), "score": 0, "pids": set(), "reasons": set()})
    for r in rows:
        x = by_ip[r["remote_ip"]]
        x["events"] += 1
        x["ports"].add(r["remote_port"])
        x["score"] = max(x["score"], r["score"])
        x["pids"].update(r.get("pids", []))
        x["reasons"].update(r.get("reasons", []))

    print("\n=== ANDROID C2 HUNTER REPORT ===")
    for ip, x in sorted(by_ip.items(), key=lambda z: z[1]["score"], reverse=True):
        print(f"\nIP: {ip}")
        print(f"  score   : {x['score']}")
        print(f"  events  : {x['events']}")
        print(f"  ports   : {sorted(x['ports'])}")
        print(f"  PIDs    : {sorted(x['pids'])}")
        print(f"  reasons : {', '.join(sorted(x['reasons']))}")

def main():
    ap = argparse.ArgumentParser(description="Android APK C2 Hunter")
    sp = ap.add_subparsers(dest="mode", required=True)

    p = sp.add_parser("static")
    p.add_argument("apk")
    p.add_argument("-o", "--out", default="c2hunter-static")
    p.add_argument("--iocs", default="")

    p = sp.add_parser("monitor")
    p.add_argument("-o", "--out", default="c2hunter-live")
    p.add_argument("-i", "--interval", type=int, default=2)
    p.add_argument("-t", "--duration", type=int, default=0)
    p.add_argument("--iocs", default="")

    p = sp.add_parser("capture")
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("-o", "--out", default="c2hunter-capture")
    p.add_argument("-t", "--duration", type=int, default=60)

    p = sp.add_parser("report")
    p.add_argument("-o", "--out", default="c2hunter-live")

    a = ap.parse_args()

    if a.mode == "static":
        static_apk(Path(a.apk), Path(a.out), load_iocs(a.iocs))
    elif a.mode == "monitor":
        return monitor(Path(a.out), a.interval, a.duration, load_iocs(a.iocs))
    elif a.mode == "capture":
        return capture(Path(a.out), a.interface, a.duration)
    elif a.mode == "report":
        report(Path(a.out))

if __name__ == "__main__":
    raise SystemExit(main() or 0)
