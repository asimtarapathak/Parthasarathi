import os
import platform
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformRuntime:
    os_key: str
    display_name: str
    is_server: bool
    support_level: str
    note: str


def _detect_windows_server() -> bool:
    """Best-effort Windows product type detection.

    ProductType values:
    1 = workstation, 2 = domain controller, 3 = server.
    """
    if os.name != "nt":
        return False

    try:
        import subprocess

        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_OperatingSystem).ProductType",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        out = (res.stdout or "").strip()
        m = re.search(r"\b([123])\b", out)
        return bool(m and int(m.group(1)) in (2, 3))
    except Exception:
        return False


def detect_platform_runtime() -> PlatformRuntime:
    system = platform.system().lower()

    if system == "windows":
        is_server = _detect_windows_server()
        if is_server:
            return PlatformRuntime(
                os_key="windows-server",
                display_name="Windows Server",
                is_server=True,
                support_level="stable",
                note="Server and AD-focused tier enabled.",
            )
        return PlatformRuntime(
            os_key="windows",
            display_name="Windows",
            is_server=False,
            support_level="stable",
            note="Windows workstation workflow enabled.",
        )

    if system == "linux":
        return PlatformRuntime(
            os_key="linux",
            display_name="Linux",
            is_server=False,
            support_level="stable",
            note="Linux workstation workflow enabled.",
        )

    if system == "darwin":
        return PlatformRuntime(
            os_key="macos",
            display_name="macOS",
            is_server=False,
            support_level="stable",
            note="macOS workstation workflow enabled.",
        )

    return PlatformRuntime(
        os_key="unknown",
        display_name=platform.system() or "Unknown OS",
        is_server=False,
        support_level="unsupported",
        note="Current OS is not supported by this build.",
    )
