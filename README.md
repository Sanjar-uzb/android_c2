# Android C2 Hunter

A lightweight Android C2 hunting toolkit for static APK triage, live ADB socket correlation, and Frida-based runtime network tracing.

## Features

- APK static analysis for IPs, URLs, domains, and SHA256 hashes
- Android live socket analysis via ADB /proc/net
- Frida runtime hooks for connect(), getaddrinfo(), and SSL calls
- IOC matching from local files in the iocs folder
- Risk scoring and summarization
- JSON, CSV, and HTML report generation
- Ready-to-run Python CLI structure

## Project layout

```text
android-c2-hunter/
├── android_c2_hunter.py
├── requirements.txt
├── README.md
├── LICENSE
├── config/
│   ├── config.yaml
│   ├── suspicious_ports.txt
│   └── common_ports.txt
├── iocs/
│   ├── ips.txt
│   ├── domains.txt
│   ├── urls.txt
│   └── hashes.txt
├── hunter/
│   ├── __init__.py
│   ├── adb.py
│   ├── device.py
│   ├── processes.py
│   ├── sockets.py
│   ├── packages.py
│   ├── filesystem.py
│   ├── static/
│   ├── dynamic/
│   ├── network/
│   ├── detection/
│   ├── evidence/
│   └── reporting/
├── frida/
│   ├── network.js
│   ├── dns.js
│   ├── tls.js
│   ├── java_network.js
│   └── native_network.js
├── tests/
│   ├── test_proc_net.py
│   ├── test_ioc.py
│   ├── test_scoring.py
│   └── test_reporting.py
├── cases/
│   └── YYYYMMDD-HHMMSS/
└──
```

## Requirements

- Python 3.10+
- ADB installed and added to PATH
- Android device connected via USB debugging
- Optional: Frida installed on the host and device runtime prepared for instrumentation
- Optional: tcpdump for packet capture mode

## Installation

Windows (PowerShell):

```powershell
cd C:\path\to\android-c2-hunter
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:

```bash
cd /path/to/android-c2-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Device preparation

Check ADB:

```bash
adb devices
```

If the device is not listed, enable USB debugging and allow authorization.

For Frida runtime mode, the target app must be installed on the device and the app package name known.

## Run the static analyzer

```bash
python android_c2_hunter.py static path/to/app.apk --iocs iocs
```

This extracts:
- APK SHA256
- IPs
- URLs
- domains
- IOC matches

Output is written to the chosen directory, for example:

```bash
python android_c2_hunter.py static path/to/app.apk --iocs iocs -o cases/out_static
```

## Run the live ADB monitor

```bash
python android_c2_hunter.py monitor -i 2 -t 30 -p com.example.app -o cases/out_monitor --iocs iocs
```

Arguments:
- -i / --interval: polling interval in seconds
- -t / --duration: total test duration in seconds
- -p / --package: package name to filter on (optional)
- -o / --out: output directory
- --iocs: IOC directory or file path root

## Run the Frida runtime hook

```bash
python android_c2_hunter.py frida -p com.example.app -t 30 -o cases/out_frida --iocs iocs
```

This hooks the app at runtime and logs network-related calls such as:
- connect()
- getaddrinfo()
- SSL/TLS connect flows

It writes a Frida JSONL result and generates a report HTML file in the output folder.

## Run the tcpdump capture mode

```bash
python android_c2_hunter.py capture -i wlan0 -t 30 -o cases/out_capture
```

This captures traffic using tcpdump and saves a PCAP to the output directory.

## View generated report artifacts

```bash
python android_c2_hunter.py report -o cases/out_frida
```

This checks the output directory for generated artifacts such as:
- report.html
- adb_monitor.json
- frida_summary.json

## Run tests

```bash
py -3 -m pytest -q
```

## Example full workflow

```powershell
cd C:\path\to\android-c2-hunter
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python android_c2_hunter.py static .\samples\app.apk --iocs .\iocs -o .\cases\out_static
python android_c2_hunter.py frida -p com.example.app -t 30 -o .\cases\out_frida --iocs .\iocs
python android_c2_hunter.py monitor -i 2 -t 30 -p com.example.app -o .\cases\out_monitor --iocs .\iocs
python android_c2_hunter.py report -o .\cases\out_frida
```

## Notes

- This project is intended for authorized security testing and malware analysis only.
- Frida runtime monitoring requires a connected physical Android device or emulator.
- Real-world detection is heuristic and should be combined with manual verification and broader threat intel.

## License

MIT
