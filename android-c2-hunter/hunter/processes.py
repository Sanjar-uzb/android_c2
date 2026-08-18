import re
from collections import defaultdict
from typing import DefaultDict, Dict, Set

from hunter.adb import adb_shell


def pid_inodes() -> DefaultDict[str, Set[str]]:
    script = r'''for p in /proc/[0-9]*; do pid=${p##*/}; for f in "$p"/fd/*; do x=$(readlink "$f" 2>/dev/null); case "$x" in socket:\[*\]) echo "$pid ${x#socket:[}";; esac; done; done'''
    rc, out, _ = adb_shell("sh -c " + repr(script), timeout=30)
    mapping: DefaultDict[str, Set[str]] = defaultdict(set)
    if rc != 0:
        return mapping
    for line in out.splitlines():
        match = re.match(r"^(\d+)\s+(\d+)", line.strip())
        if match:
            mapping[match.group(2)].add(match.group(1))
    return mapping


def process_map() -> Dict[str, str]:
    rc, out, _ = adb_shell("ps -A -o USER,PID,NAME 2>/dev/null || ps -A", timeout=20)
    mapping: Dict[str, str] = {}
    if rc != 0:
        return mapping
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and parts[1].isdigit():
            mapping[parts[1]] = parts[-1]
    return mapping
