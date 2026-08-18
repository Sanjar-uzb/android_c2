import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set


DANGEROUS_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
}

C2_PERSISTENCE_INDICATORS = {
    "BOOT_COMPLETED",
    "RECEIVE_BOOT_COMPLETED",
    "android.intent.action.BOOT_COMPLETED",
    "com.example.service",
    "FOREGROUND_SERVICE",
    "AccessibilityService",
}


def _parse_manifest_xml(xml_data: bytes) -> Dict[str, Any]:
    """Parse AndroidManifest.xml using naive XML extraction."""
    result = {
        "permissions": [],
        "services": [],
        "receivers": [],
        "activities": [],
        "providers": [],
        "package": "",
        "version_code": "",
        "version_name": "",
        "dangerous_perms": [],
        "exported_components": [],
        "receivers_with_boot": [],
        "services_foreground": [],
    }
    
    try:
        text = xml_data.decode("utf-8", errors="ignore")
        
        # Extract manifest attributes
        pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', text)
        if pkg_match:
            result["package"] = pkg_match.group(1)
        
        ver_match = re.search(r'android:versionCode\s*=\s*["\']([^"\']+)["\']', text)
        if ver_match:
            result["version_code"] = ver_match.group(1)
        
        vname_match = re.search(r'android:versionName\s*=\s*["\']([^"\']+)["\']', text)
        if vname_match:
            result["version_name"] = vname_match.group(1)
        
        # Extract permissions
        for perm_match in re.finditer(r'<uses-permission[^>]*android:name\s*=\s*["\']([^"\']+)["\']', text):
            perm = perm_match.group(1)
            result["permissions"].append(perm)
            if perm in DANGEROUS_PERMISSIONS:
                result["dangerous_perms"].append(perm)
        
        # Extract services
        for service_match in re.finditer(r'<service[^>]*android:name\s*=\s*["\']([^"\']+)["\'][^>]*(?:android:exported\s*=\s*["\']true["\'][^>]*)?[^>]*>', text):
            service = service_match.group(1)
            result["services"].append(service)
            if 'android:exported="true"' in service_match.group(0):
                result["exported_components"].append(f"service:{service}")
            if 'FOREGROUND_SERVICE' in service_match.group(0) or 'foreground' in service_match.group(0).lower():
                result["services_foreground"].append(service)
        
        # Extract receivers
        for recv_match in re.finditer(r'<receiver[^>]*android:name\s*=\s*["\']([^"\']+)["\'][^>]*(?:android:exported\s*=\s*["\']true["\'][^>]*)?[^>]*>', text):
            receiver = recv_match.group(1)
            result["receivers"].append(receiver)
            if 'android:exported="true"' in recv_match.group(0):
                result["exported_components"].append(f"receiver:{receiver}")
            if 'BOOT_COMPLETED' in recv_match.group(0):
                result["receivers_with_boot"].append(receiver)
        
        # Extract activities
        for act_match in re.finditer(r'<activity[^>]*android:name\s*=\s*["\']([^"\']+)["\']', text):
            activity = act_match.group(1)
            result["activities"].append(activity)
        
        # Extract providers
        for prov_match in re.finditer(r'<provider[^>]*android:name\s*=\s*["\']([^"\']+)["\']', text):
            provider = prov_match.group(1)
            result["providers"].append(provider)
    
    except Exception:
        pass
    
    return result


def extract_manifest(apk_path: str | Path) -> Dict[str, Any]:
    """Extract AndroidManifest.xml from APK and analyze."""
    apk_path = Path(apk_path)
    result = {
        "manifest": {},
        "c2_score": 0,
        "warnings": [],
    }
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if 'AndroidManifest.xml' not in zf.namelist():
                result["warnings"].append("AndroidManifest.xml not found")
                return result
            
            manifest_data = zf.read('AndroidManifest.xml')
            result["manifest"] = _parse_manifest_xml(manifest_data)
            
            manifest = result["manifest"]
            
            # Score based on manifest analysis
            if "INTERNET" in manifest.get("permissions", []):
                result["c2_score"] += 5
            
            if manifest.get("dangerous_perms"):
                result["c2_score"] += len(manifest["dangerous_perms"]) * 2
            
            if manifest.get("receivers_with_boot"):
                result["c2_score"] += 10
            
            if manifest.get("services_foreground"):
                result["c2_score"] += 5
            
            if manifest.get("exported_components"):
                result["c2_score"] += len(manifest["exported_components"]) * 3
    
    except Exception as e:
        result["warnings"].append(f"Error parsing manifest: {e}")
    
    return result
