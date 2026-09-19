import sys
import time
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# UTF-8 for Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from config import PROXY_HOST, PROXY_PORT
from adblock_engine import AdBlockEngine
from proxy_tunnel import JevVPNTunnel
from system_proxy import enable_system_proxy, disable_system_proxy, is_proxy_enabled

console = Console()

def cmd_test_domain(domain: str):
    engine = AdBlockEngine()
    is_blocked, cat, rule = engine.is_blocked(domain, enable_ai=True)
    color = "red" if is_blocked else "green"
    badge = "BLOCKED" if is_blocked else "ALLOWED"
    
    console.print(Panel(
        f"[bold]Domain:[/bold] {domain}\n"
        f"[bold]Disposition:[/bold] [{color}]{badge}[/{color}]\n"
        f"[bold]Category:[/bold] {cat}\n"
        f"[bold]Matched Rule / Engine:[/bold] {rule or 'None (Clean)'}",
        title="Jev-VPN AdShield Triage"
    ))

def cmd_start(port: int, enable_sys: bool = True):
    console.print(Panel(
        f"[bold cyan]🛡️ Starting Jev-VPN Privacy Tunnel & AdBlock Shield on {PROXY_HOST}:{port}...[/bold cyan]\n"
        f"[dim]DNS Protection: Active | EasyList: Loaded | AI Zero-Day Classifier: Ready[/dim]",
        title="Jev-VPN Core"
    ))

    tunnel = JevVPNTunnel(port=port)
    tunnel.start()

    if enable_sys:
        ok, msg = enable_system_proxy(port=port)
        if ok:
            console.print("[bold green]✅ Windows System Proxy Activated (All apps & browsers routing through Jev-VPN)[/bold green]")
        else:
            console.print(f"[yellow]⚠️ {msg}[/yellow]")

    console.print("[cyan]Press Ctrl+C to disconnect and restore direct internet connection...[/cyan]\n")

    try:
        while True:
            time.sleep(3.0)
            st = tunnel.stats.get_summary()
            sys.stdout.write(
                f"\r[VPN ACTIVE] Requests: {st['total_requests']} | "
                f"Ads Blocked: {st['ads_blocked']} | "
                f"Trackers: {st['trackers_blocked']} | "
                f"Saved: ~{st['saved_mb']} MB"
            )
            sys.stdout.flush()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Stopping Jev-VPN Privacy Tunnel...[/yellow]")
    finally:
        tunnel.stop()
        if enable_sys:
            disable_system_proxy()
            console.print("[bold green]✅ Windows System Proxy Disabled. Direct connection restored cleanly.[/bold green]")

def main():
    parser = argparse.ArgumentParser(description="Jev-VPN: Autonomous AI Privacy Tunnel & Smart Ad/Tracker Shield")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Start
    start_parser = subparsers.add_parser("start", help="Start the VPN tunnel & adblock shield")
    start_parser.add_argument("--port", type=int, default=PROXY_PORT, help="Proxy port (default: 8080)")
    start_parser.add_argument("--no-system-proxy", action="store_true", help="Do not set Windows system proxy automatically")

    # Test
    test_parser = subparsers.add_parser("test", help="Test whether a domain is recognized as an ad/tracker")
    test_parser.add_argument("domain", type=str, help="Domain to inspect (e.g. adservice.google.com)")

    # System Proxy
    sp_parser = subparsers.add_parser("system-proxy", help="Manage Windows system proxy")
    sp_parser.add_argument("action", choices=["on", "off", "status"], help="Enable, disable, or check status")

    # Whitelist / Blocklist
    wl_parser = subparsers.add_parser("whitelist", help="Add domain to whitelist")
    wl_parser.add_argument("domain", type=str, help="Domain to whitelist")

    bl_parser = subparsers.add_parser("blocklist", help="Add domain to custom blocklist")
    bl_parser.add_argument("domain", type=str, help="Domain to block")

    # GUI
    subparsers.add_parser("gui", help="Launch the Jev-VPN Cyber Desktop GUI")

    args = parser.parse_args()

    if not args.command or args.command == "gui":
        from gui import launch_gui
        launch_gui()
        return

    if args.command == "test":
        cmd_test_domain(args.domain)

    elif args.command == "start":
        cmd_start(port=args.port, enable_sys=not args.no_system_proxy)

    elif args.command == "system-proxy":
        if args.action == "on":
            ok, msg = enable_system_proxy()
            console.print(f"[{'green' if ok else 'red'}]{msg}[/{'green' if ok else 'red'}]")
        elif args.action == "off":
            ok, msg = disable_system_proxy()
            console.print(f"[{'green' if ok else 'red'}]{msg}[/{'green' if ok else 'red'}]")
        elif args.action == "status":
            enabled, srv = is_proxy_enabled()
            if enabled:
                console.print(f"[bold green]Proxy is ENABLED[/bold green] -> {srv}")
            else:
                console.print("[bold yellow]Proxy is DISABLED (Direct connection)[/bold yellow]")

    elif args.command == "whitelist":
        engine = AdBlockEngine()
        engine.add_to_whitelist(args.domain)
        console.print(f"[green]Added '{args.domain}' to whitelist.[/green]")

    elif args.command == "blocklist":
        engine = AdBlockEngine()
        engine.add_to_custom_blocks(args.domain)
        console.print(f"[red]Added '{args.domain}' to custom blocklist.[/red]")

if __name__ == "__main__":
    main()
