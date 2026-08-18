#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from hunter.adb import adb_devices, adb_shell
from hunter.detection.ioc import load_ioc_sets
from hunter.detection.scoring import score_connection
from hunter.dynamic.frida import run_frida_monitor
from hunter.network.connections import summarize_connections
from hunter.network.tcpdump import capture_tcpdump
from hunter.reporting.html import write_html_report
from hunter.reporting.summary import build_summary
from hunter.sockets import get_android_sockets
from hunter.static.apk import extract_static_apk_info


def _load_iocs(ioc_path: str | None):
    if not ioc_path:
        return set()
    ioc_dir = Path(ioc_path)
    if not ioc_dir.exists():
        return set()
    ioc_sets = load_ioc_sets(ioc_dir)
    return ioc_sets['ips'] | ioc_sets['domains'] | ioc_sets['urls'] | ioc_sets['hashes']


def _write_json(path: str | Path, payload):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    return str(p)


def cmd_static(apk: str, out: str, ioc_path: str | None):
    iocs = _load_iocs(ioc_path)
    result = extract_static_apk_info(apk, iocs)
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    _write_json(out_path / 'static_iocs.json', result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def cmd_monitor(interval: int, duration: int, package: str, out: str, ioc_path: str | None):
    devices = adb_devices()
    if not devices:
        print('[-] No ADB device connected. Use adb devices first.')
        return 1

    iocs = _load_iocs(ioc_path)
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    events = []
    seen = set()
    start = datetime.now(timezone.utc)
    end_time = None if duration <= 0 else start.timestamp() + duration

    print(f"[+] Monitoring Android sockets for package={package or 'all'}")
    while True:
        for row in get_android_sockets(package=package):
            ip = row.get('remote_ip')
            if not ip or ip in {'0.0.0.0', '::'}:
                continue
            key = (row.get('proto'), row.get('local_ip'), row.get('local_port'), ip, row.get('remote_port'), row.get('state'), row.get('inode'), row.get('package'))
            if key in seen:
                continue
            seen.add(key)
            repeat_count = sum(1 for item in events if item.get('remote_ip') == ip and item.get('remote_port') == row.get('remote_port'))
            score, reasons = score_connection({**row, 'remote_host': row.get('package') or row.get('remote_ip')}, repeat_count, iocs)
            rec = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': 'adb',
                'remote_ip': ip,
                'remote_port': row.get('remote_port', 0),
                'proto': row.get('proto', 'tcp'),
                'score': score,
                'reasons': reasons,
                'ioc': bool(ip in iocs),
                'uid': row.get('uid'),
                'inode': row.get('inode'),
                'package': row.get('package', ''),
                'pid': row.get('pid', ''),
                'pids': row.get('pids', []),
            }
            events.append(rec)
            print(json.dumps(rec, ensure_ascii=False))

        if end_time and datetime.now(timezone.utc).timestamp() >= end_time:
            break
        import time as _time
        _time.sleep(max(1, interval))

    summary = build_summary(events)
    summary['records'] = events
    _write_json(out_path / 'adb_monitor.json', summary)
    html = write_html_report({'summary': summary, 'rows': events}, str(out_path / 'report.html'))
    print(f"[+] ADB monitor summary saved: {out_path / 'adb_monitor.json'}")
    print(f"[+] HTML report saved: {html}")
    return 0


def cmd_frida(package: str, duration: int, out: str, ioc_path: str | None):
    iocs = _load_iocs(ioc_path)
    records = run_frida_monitor(package, duration, iocs, out)
    summary = build_summary(records)
    _write_json(Path(out) / 'frida_summary.json', summary)
    html = write_html_report({'summary': summary, 'rows': records}, str(Path(out) / 'report.html'))
    print(f"[+] captured {len(records)} Frida events")
    print(f"[+] HTML report saved: {html}")
    return 0


def cmd_capture(interface: str, duration: int, out: str):
    path = capture_tcpdump(interface, duration, out)
    print(f"[+] PCAP saved to: {path}")
    return 0


def cmd_report(out: str):
    out_path = Path(out)
    candidates = []
    for name in ['adb_monitor.json', 'frida_summary.json', 'report.html']:
        p = out_path / name
        if p.exists():
            candidates.append(str(p))
    if not candidates:
        print('[-] No report artifacts found in output directory.')
        return 1
    print('[+] Available report artifacts:')
    for item in candidates:
        print('   -', item)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description='Android C2 Hunter')
    subparsers = parser.add_subparsers(dest='mode', required=True)

    static = subparsers.add_parser('static', help='analyse APK statically')
    static.add_argument('apk')
    static.add_argument('-o', '--out', default='cases/out_static')
    static.add_argument('--iocs', default='')

    monitor = subparsers.add_parser('monitor', help='monitor live Android sockets')
    monitor.add_argument('-i', '--interval', type=int, default=2)
    monitor.add_argument('-t', '--duration', type=int, default=30)
    monitor.add_argument('-p', '--package', default='')
    monitor.add_argument('-o', '--out', default='cases/out_monitor')
    monitor.add_argument('--iocs', default='')

    frida = subparsers.add_parser('frida', help='attach Frida to a package and trace network calls')
    frida.add_argument('-p', '--package', required=True)
    frida.add_argument('-t', '--duration', type=int, default=30)
    frida.add_argument('-o', '--out', default='cases/out_frida')
    frida.add_argument('--iocs', default='')

    capture = subparsers.add_parser('capture', help='capture traffic with tcpdump')
    capture.add_argument('-i', '--interface', required=True)
    capture.add_argument('-t', '--duration', type=int, default=30)
    capture.add_argument('-o', '--out', default='cases/out_capture')

    report = subparsers.add_parser('report', help='show available artifacts for a case')
    report.add_argument('-o', '--out', default='cases/out_monitor')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.mode == 'static':
        return cmd_static(args.apk, args.out, args.iocs)
    if args.mode == 'monitor':
        return cmd_monitor(args.interval, args.duration, args.package, args.out, args.iocs)
    if args.mode == 'frida':
        return cmd_frida(args.package, args.duration, args.out, args.iocs)
    if args.mode == 'capture':
        return cmd_capture(args.interface, args.duration, args.out)
    if args.mode == 'report':
        return cmd_report(args.out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
