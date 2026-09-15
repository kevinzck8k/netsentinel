#!/usr/bin/env python3
"""
Automated fault injector for the Containerlab FRR BGP lab.

Scenarios
---------
  bgp-shutdown   — `neighbor <peer> shutdown` on a node (control-plane fault)
  iface-down     — `ip link set eth1 down` (data-plane / link fault)
  bgp-clear      — `clear ip bgp *` (session reset / flap)
  recover        — restore interface + no neighbor shutdown
  full-demo      — inject iface-down, emit syslog to pipeline, wait, recover

Usage
-----
  python fault_injector.py list
  python fault_injector.py inject --scenario iface-down --node r1
  python fault_injector.py inject --scenario bgp-shutdown --node r1 --peer 192.168.12.2
  python fault_injector.py recover --node r1
  python fault_injector.py full-demo --notify-pipeline
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from config import get_settings
from tools import resolve_container_name

app = typer.Typer(
    name="fault-injector",
    help="Containerlab FRR fault injection utilities",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
logger = logging.getLogger(__name__)


class Scenario(str, Enum):
    BGP_SHUTDOWN = "bgp-shutdown"
    IFACE_DOWN = "iface-down"
    BGP_CLEAR = "bgp-clear"
    RECOVER = "recover"
    FULL_DEMO = "full-demo"


DEFAULT_PEERS = {
    "r1": "192.168.12.2",
    "r2": "192.168.12.1",
}


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------


class InjectorError(RuntimeError):
    pass


def _require_docker() -> None:
    if shutil.which("docker") is None:
        raise InjectorError("docker CLI not found in PATH")


def docker_exec(node: str, *args: str, check: bool = True) -> str:
    """Run `docker exec` against clab-telco-aiops-<node>."""
    _require_docker()
    container = resolve_container_name(node)
    cmd = ["docker", "exec", container, *args]
    logger.info("exec: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise InjectorError(f"Timeout: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise InjectorError("docker not available") from exc

    if check and proc.returncode != 0:
        raise InjectorError(
            f"Command failed (rc={proc.returncode}): {proc.stderr or proc.stdout}"
        )
    return (proc.stdout or "").strip()


def vtysh(node: str, *commands: str) -> str:
    """Execute one or more vtysh -c commands."""
    args: list[str] = ["vtysh"]
    for c in commands:
        args.extend(["-c", c])
    return docker_exec(node, *args)


def container_running(node: str) -> bool:
    container = resolve_container_name(node)
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip().lower() == "true"


# ---------------------------------------------------------------------------
# Fault actions
# ---------------------------------------------------------------------------


def inject_bgp_shutdown(node: str, peer: str) -> None:
    console.print(f"[red]INJECT[/] BGP neighbor shutdown on {node} peer={peer}")
    vtysh(
        node,
        "configure terminal",
        f"router bgp {'65001' if node == 'r1' else '65002'}",
        f"neighbor {peer} shutdown",
        "end",
        "write memory",
    )


def inject_iface_down(node: str, interface: str = "eth1") -> None:
    console.print(f"[red]INJECT[/] interface {interface} DOWN on {node}")
    docker_exec(node, "ip", "link", "set", interface, "down")


def inject_bgp_clear(node: str) -> None:
    console.print(f"[red]INJECT[/] clear ip bgp * on {node}")
    vtysh(node, "clear ip bgp *")


def recover_node(node: str, peer: Optional[str] = None, interface: str = "eth1") -> None:
    peer = peer or DEFAULT_PEERS.get(node, "192.168.12.2")
    asn = "65001" if node == "r1" else "65002"
    console.print(f"[green]RECOVER[/] {node}: bring up {interface} + no neighbor shutdown")
    docker_exec(node, "ip", "link", "set", interface, "up", check=False)
    # Re-add IP in case the link flap wiped addresses (depends on netns setup)
    ip = "192.168.12.1/30" if node == "r1" else "192.168.12.2/30"
    docker_exec(node, "ip", "addr", "add", ip, "dev", interface, check=False)
    try:
        vtysh(
            node,
            "configure terminal",
            f"router bgp {asn}",
            f"no neighbor {peer} shutdown",
            "end",
        )
    except InjectorError as exc:
        console.print(f"[yellow]vtysh recover warning:[/] {exc}")


def emit_syslog_notification(
    node: str,
    scenario: Scenario,
    *,
    use_udp: bool = False,
    use_redis: bool = True,
) -> None:
    """Push a synthetic syslog describing the injected fault to the pipeline."""
    peer = DEFAULT_PEERS.get(node, "192.168.12.2")
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

    if scenario == Scenario.IFACE_DOWN:
        body = (
            f"<{166}>{ts} {node} zebra[10]: "
            f"%LINK-3-UPDOWN: Interface eth1, changed state to down "
            f"(BGP peer {peer} will drop)"
        )
    elif scenario == Scenario.BGP_SHUTDOWN:
        body = (
            f"<{166}>{ts} {node} bgpd[42]: "
            f"%BGP-5-ADJCHANGE: neighbor {peer} Down - Admin shutdown"
        )
    elif scenario == Scenario.BGP_CLEAR:
        body = (
            f"<{165}>{ts} {node} bgpd[42]: "
            f"%BGP-5-ADJCHANGE: neighbor {peer} Down - Cleared by operator"
        )
    else:
        body = f"<{166}>{ts} {node} aiops: fault scenario={scenario.value}"

    console.print(f"[cyan]NOTIFY[/] {body}")

    if use_redis:
        try:
            from redis_bus import RedisStreamBus

            bus = RedisStreamBus()
            bus.ensure_consumer_group()
            bus.publish_raw(body, source_ip="fault-injector")
            bus.close()
            console.print("[green]✓[/] Published to Redis Streams")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Redis notify failed:[/] {exc}")

    if use_udp:
        import socket

        settings = get_settings()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(
                body.encode("utf-8"),
                ("127.0.0.1", settings.syslog_bind_port),
            )
            sock.close()
            console.print(
                f"[green]✓[/] UDP syslog → 127.0.0.1:{settings.syslog_bind_port}"
            )
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]UDP notify failed:[/] {exc}")


def show_bgp(node: str) -> None:
    try:
        out = vtysh(node, "show ip bgp summary")
        console.print(f"[bold]{node} BGP summary[/]\n{out}")
    except InjectorError as exc:
        console.print(f"[yellow]{node}: {exc}[/]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.command("list")
def cmd_list() -> None:
    """Show available scenarios and lab node status."""
    table = Table(title="Fault Injection Scenarios")
    table.add_column("Scenario")
    table.add_column("Description")
    table.add_row("bgp-shutdown", "Admin-shutdown BGP neighbor (control plane)")
    table.add_row("iface-down", "ip link set eth1 down (data plane)")
    table.add_row("bgp-clear", "clear ip bgp * (forced flap)")
    table.add_row("recover", "Restore iface + no neighbor shutdown")
    table.add_row("full-demo", "iface-down → notify → wait → recover")
    console.print(table)

    status = Table(title="Lab Node Status")
    status.add_column("Node")
    status.add_column("Container")
    status.add_column("Running")
    for node in ("r1", "r2"):
        cname = resolve_container_name(node)
        running = "yes" if container_running(node) else "no"
        status.add_row(node, cname, running)
    console.print(status)


@app.command("inject")
def cmd_inject(
    scenario: Scenario = typer.Option(..., "--scenario", "-s"),
    node: str = typer.Option("r1", "--node", "-n"),
    peer: Optional[str] = typer.Option(None, "--peer", "-p"),
    interface: str = typer.Option("eth1", "--interface", "-i"),
    notify_pipeline: bool = typer.Option(
        False,
        "--notify-pipeline",
        help="Emit synthetic syslog to Redis (+ optional UDP)",
    ),
    udp: bool = typer.Option(False, "--udp", help="Also send UDP syslog"),
) -> None:
    """Inject a single fault scenario."""
    logging.basicConfig(level=logging.INFO)
    node = node.lower()
    peer = peer or DEFAULT_PEERS.get(node, "192.168.12.2")

    if not container_running(node):
        console.print(
            f"[red]Container for {node} is not running.[/] "
            "Deploy lab first: sudo containerlab deploy -t topology.clab.yml"
        )
        raise typer.Exit(code=1)

    if scenario == Scenario.BGP_SHUTDOWN:
        inject_bgp_shutdown(node, peer)
    elif scenario == Scenario.IFACE_DOWN:
        inject_iface_down(node, interface)
    elif scenario == Scenario.BGP_CLEAR:
        inject_bgp_clear(node)
    elif scenario == Scenario.RECOVER:
        recover_node(node, peer, interface)
    elif scenario == Scenario.FULL_DEMO:
        cmd_full_demo(
            node=node,
            wait_seconds=15,
            notify_pipeline=True,
            udp=udp,
        )
        return
    else:
        raise typer.BadParameter(f"Unsupported scenario: {scenario}")

    if notify_pipeline:
        emit_syslog_notification(
            node, scenario, use_udp=udp, use_redis=True
        )

    time.sleep(1)
    show_bgp(node)


@app.command("recover")
def cmd_recover(
    node: str = typer.Option("r1", "--node", "-n"),
    peer: Optional[str] = typer.Option(None, "--peer", "-p"),
    interface: str = typer.Option("eth1", "--interface", "-i"),
) -> None:
    """Restore interface and BGP neighbor after injection."""
    logging.basicConfig(level=logging.INFO)
    recover_node(node.lower(), peer, interface)
    time.sleep(2)
    show_bgp(node.lower())
    other = "r2" if node.lower() == "r1" else "r1"
    if container_running(other):
        show_bgp(other)


@app.command("full-demo")
def cmd_full_demo(
    node: str = typer.Option("r1", "--node", "-n"),
    wait_seconds: int = typer.Option(20, "--wait"),
    notify_pipeline: bool = typer.Option(True, "--notify-pipeline/--no-notify"),
    udp: bool = typer.Option(False, "--udp"),
) -> None:
    """
    Inject iface-down, notify the AIOps pipeline, wait, then auto-recover.
    """
    logging.basicConfig(level=logging.INFO)
    node = node.lower()
    if not container_running(node):
        console.print(
            "[yellow]Lab containers not running — emitting syslog only "
            "(pipeline will use simulated telemetry).[/]"
        )
        if notify_pipeline:
            emit_syslog_notification(
                node, Scenario.IFACE_DOWN, use_udp=udp, use_redis=True
            )
        return

    console.print("[bold]=== FULL FAULT DEMO ===[/]")
    show_bgp(node)
    inject_iface_down(node, "eth1")
    if notify_pipeline:
        emit_syslog_notification(
            node, Scenario.IFACE_DOWN, use_udp=udp, use_redis=True
        )
    console.print(f"[dim]Waiting {wait_seconds}s for AIOps pipeline…[/]")
    time.sleep(wait_seconds)
    recover_node(node)
    time.sleep(5)
    show_bgp(node)
    console.print("[bold green]Demo complete.[/]")


if __name__ == "__main__":
    try:
        app()
    except InjectorError as exc:
        console.print(f"[red]Error:[/] {exc}")
        sys.exit(1)
