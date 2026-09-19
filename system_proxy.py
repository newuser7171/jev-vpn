import winreg
import struct
import ctypes
from typing import Tuple

# Windows Internet Option Constants
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37

INTERNET_SETTINGS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
CONNECTIONS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"

def _notify_windows():
    """Notifies Windows and running browsers that proxy settings have changed."""
    try:
        internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
        internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception as e:
        print(f"[SystemProxy] Error notifying Wininet: {e}")

def _pack_connections_blob(proxy_server: str, enable: bool, bypass: str = "<local>") -> bytes:
    """
    Packs the binary structure required by Windows 10/11 DefaultConnectionSettings.
    This ensures Google Chrome, Edge, and all WinINet applications immediately recognize
    the manual proxy configuration.
    """
    flags = 0x03 if enable else 0x01
    counter = 72
    p_bytes = proxy_server.encode("ascii") if enable else b""
    b_bytes = bypass.encode("ascii") if enable else b""

    buf = bytearray()
    buf.extend(struct.pack("<I", counter))       # 0..3: counter
    buf.extend(struct.pack("<I", 0))             # 4..7: reserved
    buf.extend(struct.pack("<I", flags))         # 8..11: flags (0x03=proxy, 0x01=direct)
    buf.extend(struct.pack("<I", len(p_bytes)))  # 12..15: proxy length
    buf.extend(p_bytes)                          # proxy string
    buf.extend(struct.pack("<I", len(b_bytes)))  # bypass length
    buf.extend(b_bytes)                          # bypass string
    buf.extend(b"\x00" * 36)                     # autoconfig / WPAD padding
    return bytes(buf)

def enable_system_proxy(host: str = "127.0.0.1", port: int = 8998) -> Tuple[bool, str]:
    """
    Enables Windows system proxy for all browsers and apps to route through Jev-VPN.
    Updates both standard WinINet registry and active Connections binary configuration.
    """
    proxy_val = f"{host}:{port}"
    try:
        # 1. Standard Internet Settings keys
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_val)
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
        winreg.CloseKey(key)

        # 2. Connections keys (DefaultConnectionSettings & SavedLegacySettings for Chrome/Edge/Win11)
        blob = _pack_connections_blob(proxy_val, enable=True)
        conn_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(conn_key, "DefaultConnectionSettings", 0, winreg.REG_BINARY, blob)
        winreg.SetValueEx(conn_key, "SavedLegacySettings", 0, winreg.REG_BINARY, blob)
        winreg.CloseKey(conn_key)

        _notify_windows()
        return True, f"System proxy successfully set to {proxy_val}"
    except Exception as e:
        return False, f"Failed to enable system proxy: {e}"

def disable_system_proxy() -> Tuple[bool, str]:
    """
    Disables Windows system proxy, restoring direct internet connection.
    Cleans up both standard Internet Settings and active Connections binary keys.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        blob = _pack_connections_blob("", enable=False)
        conn_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, CONNECTIONS_PATH, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(conn_key, "DefaultConnectionSettings", 0, winreg.REG_BINARY, blob)
        winreg.SetValueEx(conn_key, "SavedLegacySettings", 0, winreg.REG_BINARY, blob)
        winreg.CloseKey(conn_key)

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
