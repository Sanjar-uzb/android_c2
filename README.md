Android C2 Monitor
===================

Quick tool to monitor network IP addresses seen from an Android device connected via `adb`.

Features
- Three core modes: host `tcpdump` capture (best, requires USB tethering and `sudo`),
  adb `/proc/net` polling (works without root on device), and a Frida-based runtime
  hook mode for in-app connection tracing.
- Live output of remote IPs with simple heuristics to label likely OUT/IN connections.

Frida mode
- Add runtime hooks for `connect()` and `getaddrinfo()` from inside a target Android app.
- Useful when you want to observe C2 attempts without relying only on socket tables.
- Example:

```bash
python3 android_c2_monitor.py frida -p com.example.app -t 30 --iocs iocs.txt
```

Install Frida support:

```bash
pip install -r requirements.txt
```

Usage
1. Ensure `adb` is installed and the device is connected with USB debugging enabled.
2. Recommended: enable USB tethering on the Android device for full packet capture.
3. Run the script:

```bash
python3 android_c2_monitor.py
```

Host tcpdump mode (requires sudo and USB tethering):

```bash
sudo python3 android_c2_monitor.py
```

ADB /proc mode (no root required on device):

```bash
python3 android_c2_monitor.py --interval 2
```

Notes & limitations
- Non-rooted Android devices cannot run `tcpdump` directly without additional setup.
- The `/proc/net` polling mode uses heuristics and cannot always determine the exact
  direction or whether a remote IP is a C2 server — it reports remote IPs observed on
  the device and attempts to guess direction based on ports.
- For reliable capture, enable USB tethering or run a capture app on the device.

Implemented in the script:
- GeoIP lookup (uses `http://ip-api.com`) with caching; can be disabled with `--no-geo`.
- Simple C2 classifier that scores IPs by port, repeats, and private/public ranges.
- Optional CSV output via `--save results.csv` for later analysis.

Example:

```bash
# Run with GeoIP and save discoveries
python3 android_c2_monitor.py --interval 2 --save discoveries.csv

# Disable GeoIP lookups (offline/faster)
python3 android_c2_monitor.py --no-geo
```

Advanced options:

- Use a local MaxMind DB for faster/offline GeoIP: `--mmdb /path/GeoLite2-Country.mmdb` (requires `geoip2` Python package).
- Provide an IoC file with one IP per line: `--iocs iocs.txt`. Matches will be labeled `ioc`.
- Save JSON lines output: `--json discoveries.jsonl`.
- Save full pcap when host tcpdump mode is used: `--pcap capture.pcap` (requires USB tethering and `sudo`).

Example advanced run:

```bash
python3 android_c2_monitor.py --interval 2 --save discoveries.csv --json discoveries.jsonl --mmdb /usr/share/GeoIP/GeoLite2-Country.mmdb --iocs my_iocs.txt
```
