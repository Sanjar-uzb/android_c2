import re
from collections import defaultdict
from typing import DefaultDict, List

from hunter.adb import adb_shell


def uid_packages() -> DefaultDict[str, List[str]]:
    rc, out, _ = adb_shell("pm list packages -U", timeout=30)
    data: DefaultDict[str, List[str]] = defaultdict(list)
    if rc != 0:
        return data
    for line in out.splitlines():
        match = re.match(r"package:(.+?) uid:(\d+)", line.strip())
        if match:
            data[match.group(2)].append(match.group(1))
    return data
