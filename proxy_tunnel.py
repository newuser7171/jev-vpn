import socket
import select
import threading
import time
from typing import Dict, Any, List, Optional, Callable
from config import PROXY_HOST, PROXY_PORT, AVG_AD_PAYLOAD_KB
from adblock_engine import AdBlockEngine

class ProxyStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total_requests = 0
        self.ads_blocked = 0
        self.trackers_blocked = 0
        self.bytes_transferred = 0
        self.est_saved_kb = 0.0
        self.recent_blocks: List[Dict[str, Any]] = []

    def record_block(self, host: str, category: str, rule: str):
        with self.lock:
            self.total_requests += 1
            if "ad" in category.lower():
                self.ads_blocked += 1
            else:
                self.trackers_blocked += 1
            self.est_saved_kb += AVG_AD_PAYLOAD_KB
            ev = {
                "time": time.strftime("%H:%M:%S"),
                "domain": host,
                "category": category,
                "rule": rule
            }
            self.recent_blocks.insert(0, ev)
            if len(self.recent_blocks) > 200:
                self.recent_blocks.pop()

    def record_pass(self, bytes_count: int = 0):
        with self.lock:
            self.total_requests += 1
            self.bytes_transferred += bytes_count

    def get_summary(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "total_requests": self.total_requests,
                "ads_blocked": self.ads_blocked,
                "trackers_blocked": self.trackers_blocked,
                "saved_mb": round(self.est_saved_kb / 1024, 2),
                "transferred_mb": round(self.bytes_transferred / (1024 * 1024), 2),
                "recent_blocks": list(self.recent_blocks)
            }


class JevVPNTunnel:
    """
    High-performance multi-threaded privacy tunnel & ad-blocking proxy.
    Intercepts HTTP/HTTPS CONNECT requests, queries the AdBlock engine,
    neutralizes ads with HTTP 204 or connection termination, and securely tunnels clean traffic.
    """
    def __init__(self, host: str = PROXY_HOST, port: int = PROXY_PORT):
        self.host = host
        self.port = port
        self.adblock = AdBlockEngine()
        self.stats = ProxyStats()
        self.server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._on_block_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    def set_on_block_callback(self, cb: Callable[[Dict[str, Any]], None]):
        self._on_block_callback = cb

    def start(self):
        if self._running:
            return

        candidate_ports = [self.port, 8998, 8999, 10808, 10809, 18080, 0]
        candidate_ports = list(dict.fromkeys(candidate_ports))
        bound = False
        last_err = None

        for p in candidate_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, p))
                actual_port = sock.getsockname()[1]
                self.port = actual_port
                self.server_socket = sock
                self.server_socket.listen(128)
                bound = True
                break
            except Exception as e:
                last_err = e
                try:
                    sock.close()
                except Exception:
                    pass

        if not bound:
            raise RuntimeError(f"Unable to bind proxy tunnel to any port: {last_err}")

        self._running = True

        def listen_loop():
            while self._running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
                except Exception:
                    break

        self._thread = threading.Thread(target=listen_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _handle_client(self, client_sock: socket.socket):
        try:
            client_sock.settimeout(10.0)
            req_data = client_sock.recv(4096)
            if not req_data:
                client_sock.close()
                return

            req_str = req_data.decode("latin1", errors="ignore")
            lines = req_str.split("\r\n")
            if not lines:
                client_sock.close()
                return

            parts = lines[0].split()
            if len(parts) < 2:
                client_sock.close()
                return

            method, target = parts[0], parts[1]

            # Parse target host and port
            if method.upper() == "CONNECT":
                # HTTPS Tunnel request: host:port
                if ":" in target:
                    host, port_str = target.split(":", 1)
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    host, port = target, 443
            else:
                # HTTP Request: http://host/path or /path with Host header
                host = ""
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                if not host:
                    host = target
                if ":" in host:
                    host, port_str = host.split(":", 1)
                    port = int(port_str) if port_str.isdigit() else 80
                else:
                    port = 80

            # Ad & Tracker Interception
            is_ad, category, rule = self.adblock.is_blocked(host)
            if is_ad:
                self.stats.record_block(host, category, rule)
                if self._on_block_callback:
                    self._on_block_callback({
                        "time": time.strftime("%H:%M:%S"),
                        "domain": host,
                        "category": category,
                        "rule": rule
                    })

                if method.upper() == "CONNECT":
                    # Close connection or send 403 Forbidden to neutralize ad
                    client_sock.sendall(b"HTTP/1.1 403 Blocked by Jev-VPN AdShield\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                else:
                    # Clean 204 No Content collapses banner without errors
                    client_sock.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                client_sock.close()
                return

            # Clean Traffic -> Establish Tunnel
            self.stats.record_pass()

            if method.upper() == "CONNECT":
                self._tunnel_https(client_sock, host, port)
            else:
                self._tunnel_http(client_sock, host, port, req_data)

        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass

    def _tunnel_https(self, client_sock: socket.socket, host: str, port: int):
        remote_sock = None
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect((host, port))
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Bi-directional socket forwarding
            self._splice_sockets(client_sock, remote_sock)
        except Exception:
            pass
        finally:
            if remote_sock:
                try:
                    remote_sock.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _tunnel_http(self, client_sock: socket.socket, host: str, port: int, initial_req: bytes):
        remote_sock = None
        try:
            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_sock.settimeout(10.0)
            remote_sock.connect((host, port))
            remote_sock.sendall(initial_req)
            self._splice_sockets(client_sock, remote_sock)
        except Exception:
            pass
        finally:
            if remote_sock:
                try:
                    remote_sock.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass

    def _splice_sockets(self, s1: socket.socket, s2: socket.socket):
        sockets = [s1, s2]
        s1.setblocking(False)
        s2.setblocking(False)
        bytes_count = 0

        while self._running:
            readable, _, exceptional = select.select(sockets, [], sockets, 30.0)
            if exceptional or not readable:
                break

            for s in readable:
                other = s2 if s is s1 else s1
                try:
                    data = s.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
                    bytes_count += len(data)
                except Exception:
                    return

        self.stats.record_pass(bytes_count)
