import subprocess
from pathlib import Path


def capture_tcpdump(interface: str, duration: int, out_dir: str | Path):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap = out_dir / "traffic.pcap"
    cmd = ["tcpdump", "-i", interface, "-nn", "-U", "-w", str(pcap)]
    process = subprocess.Popen(cmd)
    try:
        if duration > 0:
            process.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=5)
    return str(pcap)
