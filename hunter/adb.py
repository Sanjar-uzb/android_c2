import subprocess
from typing import List, Tuple


def run_command(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return completed.returncode, completed.stdout, completed.stderr
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def adb_command(args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    return run_command(["adb", *args], timeout)


def adb_shell(command: str, timeout: int = 20) -> Tuple[int, str, str]:
    return adb_command(["shell", command], timeout)


def adb_devices() -> List[str]:
    rc, out, _ = adb_command(["devices"])
    if rc != 0:
        return []
    devices = []
    for line in out.splitlines():
        if "\tdevice" in line:
            devices.append(line.split()[0])
    return devices
