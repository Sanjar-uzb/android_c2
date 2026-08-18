import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set


# DEX file magic and version detection
DEX_MAGIC = b"dex\n"
C2_INDICATORS = {
    "http_libraries": [
        "okhttp3/OkHttpClient",
        "retrofit2/Retrofit",
        "android/webkit/WebView",
        "java/net/HttpURLConnection",
        "org/apache/http",
        "com/squareup/okhttp",
    ],
    "socket_apis": [
        "java/net/Socket",
        "java/net/DatagramSocket",
        "java/nio/channels/SocketChannel",
        "java/nio/channels/DatagramChannel",
    ],
    "websocket": [
        "okhttp3/websocket",
        "nv/websocket",
        "javax/websocket",
    ],
    "mqtt": [
        "paho/mqtt",
        "org/eclipse/paho",
    ],
    "dns": [
        "java/net/InetAddress",
        "getaddrinfo",
        "gethostbyname",
    ],
    "ssl_tls": [
        "javax/net/ssl/SSLSocket",
        "javax/net/ssl/SSLContext",
        "SSL_connect",
        "X509Certificate",
    ],
    "dynamic_loading": [
        "dalvik/system/DexClassLoader",
        "dalvik/system/PathClassLoader",
        "java/lang/ClassLoader",
        "java/lang/Runtime",
        "exec",
    ],
    "reflection": [
        "java/lang/Class",
        "forName",
        "getMethod",
        "invoke",
    ],
    "native": [
        "System/loadLibrary",
        "System/load",
        "JNI",
    ],
    "persistence": [
        "BOOT_COMPLETED",
        "RECEIVE_BOOT_COMPLETED",
        "WorkManager",
        "AlarmManager",
    ],
}


def _parse_dex_strings(dex_data: bytes) -> Set[str]:
    """Extract string pool from DEX file."""
    strings = set()
    try:
        if len(dex_data) < 0x70:
            return strings
        
        string_ids_off = struct.unpack("<I", dex_data[0x14:0x18])[0]
        string_ids_size = struct.unpack("<I", dex_data[0x18:0x1C])[0]
        
        if string_ids_off + 4 * string_ids_size > len(dex_data):
            return strings
        
        for i in range(min(string_ids_size, 10000)):
            offset = struct.unpack("<I", dex_data[string_ids_off + i * 4:string_ids_off + i * 4 + 4])[0]
            if offset >= len(dex_data):
                continue
            
            try:
                size_bytes = dex_data[offset:offset + 2]
                if len(size_bytes) < 1:
                    continue
                
                size = (size_bytes[0] >> 1) if len(size_bytes) >= 1 else 0
                if size > 5000 or size < 1:
                    continue
                
                string_start = offset + 1 if size_bytes[0] & 0x80 == 0 else offset + 2
                if string_start + size > len(dex_data):
                    continue
                
                s = dex_data[string_start:string_start + size].decode("utf-8", errors="ignore")
                if s:
                    strings.add(s)
            except Exception:
                continue
    except Exception:
        pass
    
    return strings


def extract_dex_metadata(apk_path: str | Path) -> Dict[str, Any]:
    """Extract DEX-level indicators from APK."""
    apk_path = Path(apk_path)
    metadata = {
        "dex_count": 0,
        "detected_libraries": set(),
        "detected_sockets": set(),
        "detected_websockets": set(),
        "detected_mqtt": set(),
        "detected_dns": set(),
        "detected_ssl": set(),
        "detected_dynamic_loading": set(),
        "detected_reflection": set(),
        "detected_native": set(),
        "detected_persistence": set(),
        "total_strings": 0,
        "c2_score": 0,
    }
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            dex_files = [name for name in zf.namelist() if name.startswith('classes') and name.endswith('.dex')]
            metadata["dex_count"] = len(dex_files)
            
            for dex_name in dex_files[:5]:
                dex_data = zf.read(dex_name)
                if not dex_data.startswith(DEX_MAGIC):
                    continue
                
                strings = _parse_dex_strings(dex_data)
                metadata["total_strings"] += len(strings)
                
                for category, indicators in C2_INDICATORS.items():
                    for indicator in indicators:
                        for string in strings:
                            if indicator.lower() in string.lower():
                                if category == "http_libraries":
                                    metadata["detected_libraries"].add(string)
                                    metadata["c2_score"] += 3
                                elif category == "socket_apis":
                                    metadata["detected_sockets"].add(string)
                                    metadata["c2_score"] += 5
                                elif category == "websocket":
                                    metadata["detected_websockets"].add(string)
                                    metadata["c2_score"] += 8
                                elif category == "mqtt":
                                    metadata["detected_mqtt"].add(string)
                                    metadata["c2_score"] += 15
                                elif category == "ssl_tls":
                                    metadata["detected_ssl"].add(string)
                                    metadata["c2_score"] += 5
                                elif category == "dynamic_loading":
                                    metadata["detected_dynamic_loading"].add(string)
                                    metadata["c2_score"] += 10
                                elif category == "reflection":
                                    metadata["detected_reflection"].add(string)
                                    metadata["c2_score"] += 8
                                elif category == "native":
                                    metadata["detected_native"].add(string)
                                    metadata["c2_score"] += 10
                                elif category == "persistence":
                                    metadata["detected_persistence"].add(string)
                                    metadata["c2_score"] += 5
                                break
    except Exception:
        pass
    
    # Convert sets to sorted lists for JSON serialization
    for key, val in metadata.items():
        if isinstance(val, set):
            metadata[key] = sorted(list(val))[:100]
    
    return metadata
