from dataclasses import dataclass, asdict
from typing import Dict, Any


@dataclass
class DeviceInfo:
    serial: str = ""
    model: str = ""
    android_version: str = ""
    sdk: str = ""
    manufacturer: str = ""
    product: str = ""
    brand: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def collect_device_info(adb_shell_func) -> DeviceInfo:
    device = DeviceInfo()
    for label, cmd in {
        "serial": "getprop ro.serialno",
        "model": "getprop ro.product.model",
        "android_version": "getprop ro.build.version.release",
        "sdk": "getprop ro.build.version.sdk",
        "manufacturer": "getprop ro.product.manufacturer",
        "product": "getprop ro.product.name",
        "brand": "getprop ro.product.brand",
    }.items():
        rc, out, _ = adb_shell_func(cmd, timeout=10)
        if rc == 0:
            setattr(device, label, out.strip())
    return device
