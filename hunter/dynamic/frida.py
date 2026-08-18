import json
import socket
import time
from pathlib import Path

from hunter.detection.scoring import score_connection

FRIDA_JS = r'''
function sockaddr_to_host(addr) {
  if (!addr || addr.isNull()) return null;
  var family = Memory.readU16(addr);
  if (family === 2) {
    var port = Memory.readU16(addr.add(2));
    var bytes = [];
    for (var i = 0; i < 4; i++) bytes.push(Memory.readU8(addr.add(4 + i)));
    return { host: bytes.join('.'), port: port };
  }
  if (family === 10) {
    var port = Memory.readU16(addr.add(2));
    var bytes = [];
    for (var i = 0; i < 16; i++) bytes.push(Memory.readU8(addr.add(8 + i)));
    return { host: bytes.map(function(v){ return (v < 16 ? '0' : '') + v.toString(16); }).join(':'), port: port };
  }
  return null;
}
function emit(kind, host, port, extra) {
  if (!host) return;
  send({ type: 'network', kind: kind, host: host, port: port || 0, extra: extra || {} });
}
function hook_libc(name) {
  try {
    var ptr = Module.findExportByName('libc.so', name);
    if (!ptr) ptr = Module.findExportByName(null, name);
    if (!ptr) return;
    Interceptor.attach(ptr, {
      onEnter: function(args) {
        if (name === 'connect') {
          var info = sockaddr_to_host(args[1]);
          if (info) emit('connect', info.host, info.port, { fd: args[0].toInt32() });
        } else if (name === 'getaddrinfo') {
          var host = args[0].isNull() ? null : Memory.readUtf8String(args[0]);
          var service = args[1].isNull() ? null : Memory.readUtf8String(args[1]);
          var port = service ? parseInt(service, 10) : 0;
          if (host) emit('getaddrinfo', host, port, {});
        }
      }
    });
  } catch (err) {
    console.log('hook failed: ' + name + ' -> ' + String(err));
  }
}
hook_libc('connect');
hook_libc('getaddrinfo');
var ssl_connect = Module.findExportByName('libssl.so', 'SSL_connect');
if (ssl_connect) {
  Interceptor.attach(ssl_connect, {
    onEnter: function() { emit('SSL_connect', 'ssl://', 443, {}); }
  });
}
'''


def load_frida_script():
    return FRIDA_JS


def run_frida_monitor(package_name: str, duration: int, iocs: set[str] | None = None, out_dir: str | None = None):
    try:
        import frida
    except Exception as exc:
        raise RuntimeError(f"Frida dependency missing: {exc}")

    out_path = Path(out_dir) if out_dir else Path("cases")
    out_path.mkdir(parents=True, exist_ok=True)
    records = []

    device = frida.get_usb_device(timeout=20)
    pid = device.spawn([package_name])
    session = device.attach(pid)
    script = session.create_script(FRIDA_JS)

    def on_message(message, data):
        if not isinstance(message, dict):
            return
        payload = message.get("payload")
        if not isinstance(payload, dict) or payload.get("type") != "network":
            return
        host = payload.get("host")
        port = int(payload.get("port", 0) or 0)
        
        # Classify host as IP or domain
        remote_ip = None
        domain = None
        try:
            __import__("ipaddress").ip_address(host)
            remote_ip = host
        except (ValueError, TypeError):
            domain = host
            try:
                info = socket.getaddrinfo(host, port or 0, type=socket.SOCK_STREAM)
                if info:
                    remote_ip = info[0][4][0]
            except Exception:
                remote_ip = "0.0.0.0"
        
        score, reasons = score_connection({"remote_ip": remote_ip, "remote_port": port, "proto": "tcp"}, 0, iocs or set())
        rec = {
            "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "source": "frida",
            "kind": payload.get("kind", "connect"),
            "remote_ip": remote_ip,
            "remote_port": port,
            "domain": domain,
            "proto": "tcp",
            "score": score,
            "reasons": reasons,
            "ioc": bool(remote_ip in (iocs or set())),
            "details": payload.get("extra", {}),
        }
        records.append(rec)
        print(json.dumps(rec, ensure_ascii=False))

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(max(5, int(duration or 30)))
    session.detach()

    out_file = out_path / "frida.jsonl"
    with out_file.open("w", encoding="utf-8") as handle:
        for item in records:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    return records
