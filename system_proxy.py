import winreg
import ctypes
from typing import Tuple

# Windows Internet Option Constants
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

INTERNET_SETTINGS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

def _notify_windows():
    """Notifies Windows and running browsers that proxy settings have changed."""
    try:
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[SystemProxy] Error notifying Wininet: {e}")

def enable_system_proxy(host: str = "127.0.0.1", port: int = 8080) -> Tuple[bool, str]:
    """
    Enables Windows system proxy for all browsers and apps to route through Jev-VPN.
    """
    proxy_val = f"{host}:{port}"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_val)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        winreg.CloseKey(key)
        _notify_windows()
        return True, f"System proxy successfully set to {proxy_val}"
    except Exception as e:
        return False, f"Failed to enable system proxy: {e}"

def disable_system_proxy() -> Tuple[bool, str]:
    """
    Disables Windows system proxy, restoring direct internet connection.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        _notify_windows()
        return True, "System proxy disabled. Direct connection restored."
    except Exception as e:
        return False, f"Failed to disable system proxy: {e}"

def is_proxy_enabled() -> Tuple[bool, str]:
    """Checks whether Windows proxy is currently active."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ)
        enable_val, _ = winreg.QueryValueEx(key, "ProxyEnable")
        server_val = ""
        try:
            server_val, _ = winreg.QueryValueEx(key, "ProxyServer")
        except Exception:
            pass
        winreg.CloseKey(key)
        return bool(enable_val), server_val
    except Exception:
        return False, ""
