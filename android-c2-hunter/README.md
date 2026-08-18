# Android C2 Hunter

A lightweight Android C2 hunting toolkit for static APK triage, live ADB socket correlation, and Frida-based runtime network tracing.

## Features

- APK static analysis: IPs, URLs, domains, SHA256
- Android live socket analysis via ADB /proc/net
- Frida runtime hooks for connect() / getaddrinfo() / SSL calls
- IOC matching against local rule files
- Risk scoring and report generation
- JSON/CSV/HTML outputs

## Layout

```text
android-c2-hunter/
├── android_c2_hunter.py
├── requirements.txt
├── README.md
├── LICENSE
├── config/
├── iocs/
├── hunter/
├── frida/
├── tests/
├── cases/
└──
```

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python android_c2_hunter.py static path/to/app.apk --iocs iocs/ips.txt
```

## Frida runtime mode

```bash
python android_c2_hunter.py frida -p com.example.app -t 30 --iocs iocs/ips.txt
```

## Monitor mode

```bash
python android_c2_hunter.py monitor -i 2 -t 30 --package com.example.app --iocs iocs/ips.txt
```

## License

MIT
