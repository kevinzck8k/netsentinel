"""
Network Diagnostic Tools — Netmiko / docker-exec / subprocess probes.

Every public tool is decorated with @traced for OpenTelemetry spans and
wrapped with tenacity retries for flaky lab connectivity.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import Settings, get_settings
from observability import traced

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lab inventory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NodeTarget:
    name: str
    host: str
    port: int = 22
    username: str = "root"
    password: str = ""
    device_type: str = "linux"
    mgmt_ip: str = ""


def load_lab_inventory(settings: Settings | None = None) -> dict[str, NodeTarget]:
    """Parse LAB_NODES_JSON into a typed inventory map."""
    settings = settings or get_settings()
    raw = json.loads(settings.lab_nodes_json)
    inventory: dict[str, NodeTarget] = {}
    for name, meta in raw.items():
        inventory[name.lower()] = NodeTarget(
            name=name.lower(),
            host=str(meta.get("host", "")),
            port=int(meta.get("port", 22)),
            username=str(meta.get("username", "root")),
            password=str(meta.get("password", "")),
            device_type=str(meta.get("device_type", "linux")),
            mgmt_ip=str(meta.get("mgmt_ip", "")),
        )
    return inventory


# ---------------------------------------------------------------------------
# Command execution backends
# ---------------------------------------------------------------------------


class DiagnosticError(RuntimeError):
    """Raised when a diagnostic probe fails after retries."""


def _docker_available() -> bool:
    return shutil.which("docker") is not None


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=6),
    retry=retry_if_exception_type((DiagnosticError, OSError, subprocess.TimeoutExpired)),
)
def _docker_exec(container: str, command: str, *, timeout: int = 30) -> str:
    """Execute a command inside a Containerlab / Docker node."""
    full_cmd = ["docker", "exec", container, "vtysh", "-c", command]
    # Fallback: if vtysh fails, try plain sh -c
    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
        # Retry via shell for non-vtysh commands
        proc2 = subprocess.run(
            ["docker", "exec", container, "sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc2.returncode != 0:
            raise DiagnosticError(
                f"docker exec failed on {container}: {proc2.stderr or proc.stderr}"
            )
        return proc2.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        raise DiagnosticError(f"Timeout executing on {container}: {command}") from exc


@retry(
    reraise=True,
    stop=stop_after_attempt(2),
    wait=wait_exponential(multiplier=0.3, min=0.3, max=2),
    retry=retry_if_exception_type((DiagnosticError, OSError)),
)
def _netmiko_exec(target: NodeTarget, command: str, *, timeout: int = 15) -> str:
    """SSH via Netmiko and run a command (vtysh -c '...' for FRR)."""
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise DiagnosticError("netmiko is not installed") from exc

    device = {
        "device_type": target.device_type,
        "host": target.host,
        "port": target.port,
        "username": target.username,
        "password": target.password,
        "timeout": timeout,
        "session_timeout": timeout,
        "conn_timeout": 10,
    }
    try:
        with ConnectHandler(**device) as conn:
            # Prefer vtysh for FRR show commands
            if command.strip().lower().startswith("show"):
                output = conn.send_command(f"vtysh -c '{command}'", read_timeout=timeout)
            else:
                output = conn.send_command(command, read_timeout=timeout)
            return str(output).strip()
    except Exception as exc:  # noqa: BLE001
        raise DiagnosticError(f"Netmiko failed on {target.name}: {exc}") from exc


def _simulated_output(device: str, command: str) -> str:
    """
    Deterministic simulated FRR output for offline demos when lab is down.
    """
    cmd = command.lower()
    is_r2 = device.lower() == "r2"
    router_id = "10.0.0.2" if is_r2 else "10.0.0.1"
    local_as = "65002" if is_r2 else "65001"
    peer_ip = "192.168.12.1" if is_r2 else "192.168.12.2"
    peer_as = "65001" if is_r2 else "65002"
    local_ip = "192.168.12.2" if is_r2 else "192.168.12.1"
    if "bgp summary" in cmd or "show ip bgp sum" in cmd:
        return (
            f"IPv4 Unicast Summary (simulated/{device}):\n"
            f"BGP router identifier {router_id}, local AS number {local_as}\n"
            "Neighbor        V         AS   MsgRcvd   MsgSent   State/PfxRcd\n"
            f"{peer_ip:<15} 4      {peer_as}         0         0   Idle         0\n"
        )
    if "bgp" in cmd:
        return (
            f"BGP table version is 0 (simulated/{device})\n"
            "No BGP prefixes present — peer session not Established\n"
        )
    if "interface" in cmd or "ip addr" in cmd:
        return (
            f"Interface eth1 (simulated/{device})\n"
            "  state: DOWN\n"
            f"  inet {local_ip}/30\n"
        )
    if "ip route" in cmd:
        return f"Codes: K - kernel (simulated/{device})\n  — empty —\n"
    return f"[simulated/{device}] OK: {command}"


# ---------------------------------------------------------------------------
# Public diagnostic tools
# ---------------------------------------------------------------------------


def resolve_container_name(device: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    return f"{settings.docker_container_prefix}{device.lower()}"


@traced("tool.run_cli_command", attributes={"component": "diagnostics"})
def run_cli_command(device: str, command: str) -> str:
    """
    Execute a diagnostic CLI command against a lab node.

    Preference order:
      1. Simulated output when offline_mode / no API lab
      2. docker exec into clab-<topo>-<node>  (prefer_docker_exec=True)
      3. Netmiko SSH to management IP
      4. Simulated offline output (last resort)
    """
    settings = get_settings()
    device = device.lower().strip()

    if settings.is_offline():
        logger.info("offline_mode: simulated output device=%s cmd=%s", device, command)
        return _simulated_output(device, command)

    inventory = load_lab_inventory(settings)

    # 1) Docker exec
    if settings.prefer_docker_exec and _docker_available():
        container = resolve_container_name(device, settings)
        try:
            output = _docker_exec(container, command)
            logger.info("docker-exec ok device=%s cmd=%s", device, command)
            return output
        except DiagnosticError as exc:
            logger.warning("docker-exec failed (%s); falling back", exc)

    # 2) Netmiko (single attempt path via reduced retries already on helper)
    target = inventory.get(device)
    if target and target.host:
        try:
            output = _netmiko_exec(target, command)
            logger.info("netmiko ok device=%s cmd=%s", device, command)
            return output
        except DiagnosticError as exc:
            logger.warning("netmiko failed (%s); falling back to simulation", exc)

    # 3) Never present fabricated data as online evidence unless explicitly
    # enabled for a lab demo.
    if settings.allow_simulated_telemetry and settings.app_env == "lab":
        logger.warning(
            "Using explicitly enabled simulated output for device=%s cmd=%s",
            device,
            command,
        )
        return _simulated_output(device, command)
    raise DiagnosticError(
        f"All telemetry backends failed for device={device} command={command!r}"
    )


@traced("tool.show_ip_bgp_summary")
def show_ip_bgp_summary(device: str) -> str:
    """Collect `show ip bgp summary` from an FRR node."""
    return run_cli_command(device, "show ip bgp summary")


@traced("tool.show_ip_bgp")
def show_ip_bgp(device: str) -> str:
    """Collect `show ip bgp` from an FRR node."""
    return run_cli_command(device, "show ip bgp")


@traced("tool.show_interface")
def show_interface(device: str, interface: str = "eth1") -> str:
    """Collect interface brief / detailed status."""
    # FRR vtysh
    return run_cli_command(device, f"show interface {interface}")


@traced("tool.show_ip_route")
def show_ip_route(device: str) -> str:
    """Collect `show ip route`."""
    return run_cli_command(device, "show ip route")


@traced("tool.ping_peer")
def ping_peer(device: str, peer_ip: str, count: int = 3) -> str:
    """ICMP reachability check from inside the node."""
    settings = get_settings()
    if settings.prefer_docker_exec and _docker_available():
        container = resolve_container_name(device, settings)
        try:
            proc = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "ping",
                    "-c",
                    str(count),
                    "-W",
                    "1",
                    peer_ip,
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            return (proc.stdout or proc.stderr or "").strip()
        except Exception as exc:  # noqa: BLE001
            logger.warning("ping failed: %s", exc)
    return f"[simulated] ping {peer_ip} from {device}: 100% packet loss"


def _probes_for_event(event_type: str) -> dict[str, Any]:
    """Select CLI probes by alarm class — Telemetry Agent's unique capability."""
    event = (event_type or "").lower()
    interface = {"show interface eth1": lambda d: show_interface(d, "eth1")}
    bgp = {
        "show ip bgp summary": show_ip_bgp_summary,
        "show ip bgp": show_ip_bgp,
    }
    route = {"show ip route": show_ip_route}
    if event in {"interface_down", "link_failure"}:
        return {**interface, **bgp}
    if event in {"auth_failure"}:
        return {**bgp, **interface}
    if event in {"ospf_adjacency_down"}:
        return {**interface, **route}
    if event in {"high_cpu", "high_memory"}:
        return {**bgp, **interface}
    if event in {"bgp_session_down", "bgp_flap", "route_withdrawal"}:
        return {**bgp, **interface, **route}
    return {**bgp, **interface, **route}


@traced("tool.collect_telemetry_bundle")
def collect_telemetry_bundle(device: str, event_type: str = "") -> dict[str, Any]:
    """
    Run an event-aware diagnostic bundle against one node.

    Returns a dict suitable for TelemetrySnapshot.raw_outputs.
    """
    commands = _probes_for_event(event_type)
    outputs: dict[str, str] = {}
    errors: list[str] = []
    for label, fn in commands.items():
        try:
            outputs[label] = fn(device)
        except Exception as exc:  # noqa: BLE001
            msg = f"{label}: {exc}"
            errors.append(msg)
            outputs[label] = f"ERROR: {exc}"
            logger.exception("Telemetry command failed: %s", msg)

    healthy = _infer_health(outputs)
    return {
        "device_name": device,
        "commands_executed": list(commands.keys()),
        "raw_outputs": outputs,
        "bgp_summary": outputs.get("show ip bgp summary"),
        "interface_status": outputs.get("show interface eth1"),
        "route_table_snippet": outputs.get("show ip route"),
        "collection_errors": errors,
        "healthy": healthy,
    }


def _infer_health(outputs: dict[str, str]) -> Optional[bool]:
    """Heuristic: Idle/Active/DOWN ⇒ unhealthy; Established ⇒ healthy."""
    blob = " ".join(outputs.values()).lower()
    if any(tok in blob for tok in ("idle", "active", "state: down", "administratively down")):
        return False
    if "established" in blob:
        return True
    return None


# LangChain StructuredTool factories (optional binding)
def get_langchain_tools() -> list[Any]:
    """Build LangChain Tool objects for agent binding."""
    try:
        from langchain_core.tools import StructuredTool
    except ImportError:
        return []

    return [
        StructuredTool.from_function(
            func=show_ip_bgp_summary,
            name="show_ip_bgp_summary",
            description="Run 'show ip bgp summary' on an FRR/network device.",
        ),
        StructuredTool.from_function(
            func=show_ip_bgp,
            name="show_ip_bgp",
            description="Run 'show ip bgp' on an FRR/network device.",
        ),
        StructuredTool.from_function(
            func=show_interface,
            name="show_interface",
            description="Show interface status (default eth1) on a device.",
        ),
        StructuredTool.from_function(
            func=show_ip_route,
            name="show_ip_route",
            description="Run 'show ip route' on a device.",
        ),
        StructuredTool.from_function(
            func=ping_peer,
            name="ping_peer",
            description="Ping a peer IP from inside a lab node.",
        ),
        StructuredTool.from_function(
            func=collect_telemetry_bundle,
            name="collect_telemetry_bundle",
            description="Collect a full BGP/interface/route diagnostic bundle.",
        ),
    ]
