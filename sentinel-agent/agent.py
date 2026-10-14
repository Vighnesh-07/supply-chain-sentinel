"""
Supply Chain Sentinel -- eBPF Monitoring Agent
================================================
FastAPI HTTP server that loads eBPF programs and exposes a REST API so that
the main monitor.py can query kernel-level security events without importing
BCC directly (BCC requires Linux + CAP_SYS_ADMIN).

Usage:
    python agent.py [--port PORT] [--container CONTAINER_NAME]
                    [--duration SECONDS] [--log-file PATH]

Example:
    python agent.py --port 7777 --container nexus-studio-app --duration 300 \\
                    --log-file /tmp/sentinel_ebpf.log
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import ipaddress
import logging
import os
import platform
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# FastAPI / Pydantic imports
# ---------------------------------------------------------------------------
from fastapi import FastAPI, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import uvicorn

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel-agent")
console = Console()

# ---------------------------------------------------------------------------
# Attempt to import EBPFMonitor from the parent project.
# The agent can be run:
#   1. Inside the Docker container where /sentinel-agent is the workdir and
#      the monitor/ tree may be bind-mounted under /monitor.
#   2. Directly from the host for development, in which case
#      monitor/utils/ebpf_monitor.py is on a relative path.
# ---------------------------------------------------------------------------
EBPF_MONITOR_CLASS = None
_import_error: str = ""

def _try_import_ebpf_monitor() -> None:
    """Try various import strategies for EBPFMonitor."""
    global EBPF_MONITOR_CLASS, _import_error

    search_paths = [
        # Bind-mount inside container
        Path("/monitor/utils"),
        # Sibling directory on host (dev mode)
        Path(__file__).parent.parent / "monitor" / "utils",
        # Already on sys.path
        None,
    ]

    for path in search_paths:
        if path is not None and path.is_dir():
            if str(path.parent) not in sys.path:
                sys.path.insert(0, str(path.parent))
        try:
            from monitor.utils.ebpf_monitor import EBPFMonitor  # type: ignore
            EBPF_MONITOR_CLASS = EBPFMonitor
            logger.info("EBPFMonitor imported from %s", path or "sys.path")
            return
        except ImportError:
            pass

    _import_error = "EBPFMonitor not found on any search path"
    logger.warning(_import_error)

_try_import_ebpf_monitor()

# ---------------------------------------------------------------------------
# BCC availability detection
# ---------------------------------------------------------------------------
BCC_AVAILABLE: bool = False
try:
    import bcc  # noqa: F401
    BCC_AVAILABLE = True
    logger.info("BCC (bpfcc) is available")
except ImportError:
    logger.warning("BCC not available -- running in fallback mode")

# ---------------------------------------------------------------------------
# Kernel version helpers
# ---------------------------------------------------------------------------

def _kernel_version() -> str:
    try:
        return platform.release()
    except Exception:
        return "unknown"


def _is_linux() -> bool:
    return sys.platform.startswith("linux")

# ---------------------------------------------------------------------------
# Severity ordering for filtering
# ---------------------------------------------------------------------------
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# ---------------------------------------------------------------------------
# In-memory circular event buffer (max 10 000 events)
# ---------------------------------------------------------------------------
EVENT_BUFFER: deque[Dict[str, Any]] = deque(maxlen=10_000)
_buffer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Global monitoring state
# ---------------------------------------------------------------------------
_monitor_instance: Any = None          # EBPFMonitor or FallbackMonitor
_monitor_thread: Optional[threading.Thread] = None
_monitoring_active: bool = False
_monitor_container_ids: List[str] = []
_monitor_log_file: Optional[str] = None

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    mode: str
    kernel: str
    bcc_available: bool
    events_captured: int
    monitoring_active: bool


class CapabilitiesResponse(BaseModel):
    mode: str
    bcc_available: bool
    ebpf_probes: List[str]
    fallback_methods: List[str]
    kernel: str
    is_linux: bool


class EventResponse(BaseModel):
    events: List[Dict]
    total: int
    filtered: int
    since: Optional[float]
    mode: str


class MonitorConfig(BaseModel):
    container_ids: List[str]
    log_file: Optional[str] = None


class MonitorStopResponse(BaseModel):
    stopped: bool
    events_captured: int
    containers_monitored: List[str]


class ClearEventsResponse(BaseModel):
    cleared: bool
    events_removed: int

# ---------------------------------------------------------------------------
# Fallback monitor using docker top polling
# ---------------------------------------------------------------------------

class FallbackMonitor:
    """
    Lightweight polling monitor used when BCC / eBPF is unavailable.
    Uses `docker top` to periodically snapshot running processes and
    detect newly spawned child processes inside the target containers.
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self, container_ids: List[str], log_file: Optional[str] = None) -> None:
        self.container_ids = container_ids
        self.log_file = log_file
        self._stop_event = threading.Event()
        self._known_pids: Dict[str, set] = {}

    def start(self) -> None:
        self._stop_event.clear()
        logger.info("[fallback] Starting docker-top polling for %s", self.container_ids)
        while not self._stop_event.is_set():
            for cid in self.container_ids:
                self._poll_container(cid)
            self._stop_event.wait(self.POLL_INTERVAL)

    def stop(self) -> None:
        self._stop_event.set()

    def _poll_container(self, container_id: str) -> None:
        try:
            result = subprocess.run(
                ["docker", "top", container_id, "-eo", "pid,ppid,user,comm,args"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return
            lines = result.stdout.strip().splitlines()
            current_pids: set = set()
            for line in lines[1:]:  # skip header
                parts = line.split(None, 4)
                if not parts:
                    continue
                pid_str = parts[0]
                try:
                    pid = int(pid_str)
                except ValueError:
                    continue
                current_pids.add(pid)
                known = self._known_pids.setdefault(container_id, set())
                if pid not in known:
                    comm = parts[3] if len(parts) > 3 else "unknown"
                    args = parts[4] if len(parts) > 4 else ""
                    event = {
                        "type": "exec",
                        "source": "fallback_docker_top",
                        "container_id": container_id,
                        "pid": pid,
                        "ppid": int(parts[1]) if len(parts) > 1 else 0,
                        "uid": parts[2] if len(parts) > 2 else "unknown",
                        "comm": comm,
                        "filename": comm,
                        "argv0": args.split()[0] if args else "",
                        "timestamp": time.time(),
                        "severity": _classify_exec_severity(comm, args),
                        "message": f"New process in {container_id}: {comm} {args}",
                    }
                    _push_event(event)
            self._known_pids[container_id] = current_pids
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------

def _push_event(event: Dict[str, Any]) -> None:
    with _buffer_lock:
        EVENT_BUFFER.append(event)


def _classify_exec_severity(comm: str, args: str) -> str:
    comm_l = comm.lower()
    args_l = args.lower()
    if any(x in comm_l for x in ("curl", "wget", "nc", "ncat", "bash", "sh", "python", "perl", "ruby")):
        if any(x in args_l for x in ("http", "https", "/dev/tcp", "-e", "exec")):
            return "CRITICAL"
        return "HIGH"
    if any(x in comm_l for x in ("apt", "pip", "npm", "yum", "dnf", "apk")):
        return "HIGH"
    return "MEDIUM"

# ---------------------------------------------------------------------------
# eBPF event callbacks (called from BCC perf_buffer polling thread)
# ---------------------------------------------------------------------------

def _on_exec_event(cpu, data, size) -> None:  # type: ignore[no-untyped-def]
    """BCC perf buffer callback for exec_events."""
    try:
        # Access fields via ctypes structure; BCC provides b.get_table() types.
        filename = data.filename.decode("utf-8", errors="replace")
        comm = data.comm.decode("utf-8", errors="replace")
        argv0 = data.argv0.decode("utf-8", errors="replace")
        event = {
            "type": "exec",
            "source": "ebpf_execve",
            "pid": data.pid,
            "ppid": data.ppid,
            "uid": data.uid,
            "comm": comm,
            "filename": filename,
            "argv0": argv0,
            "timestamp": data.timestamp / 1e9,
            "severity": _classify_exec_severity(comm, filename + " " + argv0),
            "message": f"execve: pid={data.pid} comm={comm} file={filename}",
        }
        _push_event(event)
    except Exception as exc:
        logger.debug("exec event parse error: %s", exc)


def _on_connect_event(cpu, data, size) -> None:  # type: ignore[no-untyped-def]
    """BCC perf buffer callback for connect_events."""
    try:
        src = str(ipaddress.IPv4Address(ctypes.c_uint32(data.saddr).value))
        dst = str(ipaddress.IPv4Address(ctypes.c_uint32(data.daddr).value))
        comm = data.comm.decode("utf-8", errors="replace")
        # Simple severity: non-RFC1918 destinations are HIGH
        severity = "HIGH"
        try:
            addr_obj = ipaddress.IPv4Address(dst)
            if addr_obj.is_private or addr_obj.is_loopback or addr_obj.is_link_local:
                severity = "MEDIUM"
        except Exception:
            pass
        event = {
            "type": "network",
            "source": "ebpf_tcp_connect",
            "pid": data.pid,
            "comm": comm,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": data.dport,
            "src_port": data.sport,
            "timestamp": data.timestamp / 1e9,
            "severity": severity,
            "message": f"TCP connect: pid={data.pid} comm={comm} {src}->{dst}:{data.dport}",
        }
        _push_event(event)
    except Exception as exc:
        logger.debug("connect event parse error: %s", exc)


SENSITIVE_PATH_PREFIXES = (
    "/.aws",
    "/.ssh",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root",
    "/proc/",
    "/run/secrets",
    "/var/run/secrets",
)


def _on_file_event(cpu, data, size) -> None:  # type: ignore[no-untyped-def]
    """BCC perf buffer callback for file_events."""
    try:
        filename = data.filename.decode("utf-8", errors="replace")
        # Filter to only sensitive paths
        if not any(filename.startswith(p) for p in SENSITIVE_PATH_PREFIXES):
            return
        comm = data.comm.decode("utf-8", errors="replace")
        write_access = bool(data.flags & 0x1) or bool(data.flags & 0x2)
        severity = "CRITICAL" if write_access else "HIGH"
        event = {
            "type": "file",
            "source": "ebpf_openat",
            "pid": data.pid,
            "uid": data.uid,
            "comm": comm,
            "filename": filename,
            "flags": data.flags,
            "write": write_access,
            "timestamp": data.timestamp / 1e9,
            "severity": severity,
            "message": f"sensitive file open: pid={data.pid} comm={comm} file={filename} write={write_access}",
        }
        _push_event(event)
    except Exception as exc:
        logger.debug("file event parse error: %s", exc)

# ---------------------------------------------------------------------------
# eBPF program loader
# ---------------------------------------------------------------------------

PROBE_DIR = Path(__file__).parent / "probe_programs"
_bpf_instance: Any = None   # bcc.BPF instance
_perf_thread: Optional[threading.Thread] = None
_perf_stop = threading.Event()


def _load_ebpf_programs() -> bool:
    """
    Compile and attach the three eBPF programs using BCC.
    Returns True on success.
    """
    global _bpf_instance
    if not BCC_AVAILABLE:
        return False
    try:
        import bcc  # type: ignore

        # Combine the three probe C sources
        combined_src = ""
        for probe_file in ("exec_probe.c", "connect_probe.c", "file_probe.c"):
            src_path = PROBE_DIR / probe_file
            if src_path.exists():
                combined_src += src_path.read_text() + "\n"
            else:
                logger.warning("Probe source not found: %s", src_path)

        b = bcc.BPF(text=combined_src)

        # Attach kprobes
        b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")
        b.attach_kprobe(event=b.get_syscall_fnname("openat"), fn_name="trace_openat")

        # Open perf buffers
        b["exec_events"].open_perf_buffer(_on_exec_event)
        b["connect_events"].open_perf_buffer(_on_connect_event)
        b["file_events"].open_perf_buffer(_on_file_event)

        _bpf_instance = b
        logger.info("eBPF programs loaded and kprobes attached")
        return True
    except Exception as exc:
        logger.error("Failed to load eBPF programs: %s", exc)
        return False


def _perf_poll_loop() -> None:
    """Background thread: continuously poll BCC perf buffers."""
    global _bpf_instance
    while not _perf_stop.is_set() and _bpf_instance is not None:
        try:
            _bpf_instance.perf_buffer_poll(timeout=100)
        except Exception as exc:
            logger.debug("perf_buffer_poll error: %s", exc)
            time.sleep(0.1)

# ---------------------------------------------------------------------------
# Agent mode determination
# ---------------------------------------------------------------------------

def _agent_mode() -> str:
    return "ebpf" if (BCC_AVAILABLE and _is_linux()) else "fallback"

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Supply Chain Sentinel -- eBPF Agent",
    description=(
        "Kernel-level security event collection API. "
        "Exposes eBPF-captured exec, network and file events via REST and SSE."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Startup / shutdown lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def _on_startup() -> None:
    global _perf_thread, _perf_stop

    if BCC_AVAILABLE and _is_linux():
        loaded = _load_ebpf_programs()
        if loaded:
            _perf_stop.clear()
            _perf_thread = threading.Thread(
                target=_perf_poll_loop, daemon=True, name="perf-poll"
            )
            _perf_thread.start()
            logger.info("Perf buffer polling thread started")

    _print_startup_banner()

    # Auto-start if --container CLI arg was provided
    if _CLI_ARGS and _CLI_ARGS.container:
        logger.info("Auto-starting monitoring for container: %s", _CLI_ARGS.container)
        _start_monitoring(
            container_ids=[_CLI_ARGS.container],
            log_file=_CLI_ARGS.log_file,
        )


@app.on_event("shutdown")
async def _on_shutdown() -> None:
    global _perf_stop
    _perf_stop.set()
    _stop_monitoring()
    logger.info("Sentinel agent shut down")

# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return agent health and operational mode."""
    with _buffer_lock:
        total = len(EVENT_BUFFER)
    return HealthResponse(
        status="ok",
        mode=_agent_mode(),
        kernel=_kernel_version(),
        bcc_available=BCC_AVAILABLE,
        events_captured=total,
        monitoring_active=_monitoring_active,
    )


@app.get("/capabilities", response_model=CapabilitiesResponse)
async def capabilities() -> CapabilitiesResponse:
    """Return full capability description."""
    probes = []
    if BCC_AVAILABLE and _is_linux():
        probes = ["exec_probe (execve)", "connect_probe (tcp_v4_connect)", "file_probe (openat)"]
    return CapabilitiesResponse(
        mode=_agent_mode(),
        bcc_available=BCC_AVAILABLE,
        ebpf_probes=probes,
        fallback_methods=["docker_top_polling", "proc_net_tcp"],
        kernel=_kernel_version(),
        is_linux=_is_linux(),
    )


@app.get("/events", response_model=EventResponse)
async def get_events(
    since: Optional[float] = Query(default=None, description="Unix timestamp; return events after this time"),
    severity: Optional[str] = Query(default=None, description="Minimum severity: LOW|MEDIUM|HIGH|CRITICAL"),
) -> EventResponse:
    """Return buffered events, optionally filtered by timestamp and minimum severity."""
    min_sev = SEVERITY_ORDER.get((severity or "").upper(), 0)
    with _buffer_lock:
        all_events = list(EVENT_BUFFER)
    total = len(all_events)

    filtered = all_events
    if since is not None:
        filtered = [e for e in filtered if e.get("timestamp", 0) >= since]
    if severity:
        filtered = [e for e in filtered if SEVERITY_ORDER.get(e.get("severity", "LOW"), 0) >= min_sev]

    return EventResponse(
        events=filtered,
        total=total,
        filtered=len(filtered),
        since=since,
        mode=_agent_mode(),
    )


@app.post("/monitor/start")
async def monitor_start(config: MonitorConfig) -> Dict[str, Any]:
    """Start eBPF / fallback monitoring for the specified containers."""
    success = _start_monitoring(
        container_ids=config.container_ids,
        log_file=config.log_file,
    )
    return {
        "started": success,
        "container_ids": config.container_ids,
        "mode": _agent_mode(),
    }


@app.post("/monitor/stop", response_model=MonitorStopResponse)
async def monitor_stop() -> MonitorStopResponse:
    """Stop monitoring and return a summary."""
    with _buffer_lock:
        captured = len(EVENT_BUFFER)
    containers = list(_monitor_container_ids)
    _stop_monitoring()
    return MonitorStopResponse(
        stopped=True,
        events_captured=captured,
        containers_monitored=containers,
    )


@app.get("/events/stream")
async def events_stream() -> StreamingResponse:
    """
    Server-Sent Events (SSE) stream of real-time events as they occur.
    Connect with: curl -N http://localhost:7777/events/stream
    """
    async def _generator():
        last_index = 0
        while True:
            with _buffer_lock:
                all_ev = list(EVENT_BUFFER)
            new_events = all_ev[last_index:]
            last_index = len(all_ev)
            for ev in new_events:
                import json
                yield f"data: {json.dumps(ev)}\n\n"
            await asyncio.sleep(0.2)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.delete("/events", response_model=ClearEventsResponse)
async def clear_events() -> ClearEventsResponse:
    """Clear the in-memory event buffer."""
    with _buffer_lock:
        removed = len(EVENT_BUFFER)
        EVENT_BUFFER.clear()
    return ClearEventsResponse(cleared=True, events_removed=removed)

# ---------------------------------------------------------------------------
# Internal monitoring helpers
# ---------------------------------------------------------------------------

def _start_monitoring(
    container_ids: List[str],
    log_file: Optional[str],
) -> bool:
    global _monitor_instance, _monitor_thread, _monitoring_active
    global _monitor_container_ids, _monitor_log_file

    if _monitoring_active:
        _stop_monitoring()

    _monitor_container_ids = container_ids
    _monitor_log_file = log_file

    if EBPF_MONITOR_CLASS is not None:
        # Use the full EBPFMonitor from monitor/utils/
        try:
            _monitor_instance = EBPF_MONITOR_CLASS(
                container_ids=container_ids,
                event_callback=_push_event,
                log_file=log_file,
            )
        except TypeError:
            # EBPFMonitor may have a different signature; fall through to fallback
            _monitor_instance = None

    if _monitor_instance is None:
        # Use built-in fallback
        _monitor_instance = FallbackMonitor(
            container_ids=container_ids,
            log_file=log_file,
        )

    _monitor_thread = threading.Thread(
        target=_monitor_instance.start, daemon=True, name="monitor"
    )
    _monitor_thread.start()
    _monitoring_active = True
    logger.info(
        "Monitoring started: containers=%s mode=%s", container_ids, _agent_mode()
    )
    return True


def _stop_monitoring() -> None:
    global _monitoring_active, _monitor_instance, _monitor_thread
    if _monitor_instance is not None:
        try:
            _monitor_instance.stop()
        except Exception as exc:
            logger.debug("Error stopping monitor: %s", exc)
        _monitor_instance = None
    if _monitor_thread is not None and _monitor_thread.is_alive():
        _monitor_thread.join(timeout=3)
    _monitor_thread = None
    _monitoring_active = False
    logger.info("Monitoring stopped")

# ---------------------------------------------------------------------------
# Rich startup banner
# ---------------------------------------------------------------------------

def _print_startup_banner() -> None:
    mode = _agent_mode()
    kernel = _kernel_version()

    banner_lines = [
        "[bold cyan]Supply Chain Sentinel[/bold cyan] -- eBPF Monitoring Agent",
        "",
        f"  Mode    : [bold]{'[green]eBPF (kernel-native)[/green]' if mode == 'ebpf' else '[yellow]Fallback (docker-top polling)[/yellow]'}[/bold]",
        f"  Kernel  : {kernel}",
        f"  BCC     : {'[green]Available[/green]' if BCC_AVAILABLE else '[red]Not available[/red]'}",
        "",
        "[underline]REST API Endpoints[/underline]",
    ]

    table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("Path", style="white")
    table.add_column("Description")

    endpoints = [
        ("GET",    "/health",         "Agent health and mode"),
        ("GET",    "/capabilities",   "Full capabilities dict"),
        ("GET",    "/events",         "Buffered events (filter: ?since=&severity=)"),
        ("GET",    "/events/stream",  "Server-Sent Events real-time stream"),
        ("POST",   "/monitor/start",  "Start monitoring containers"),
        ("POST",   "/monitor/stop",   "Stop monitoring + summary"),
        ("DELETE", "/events",         "Clear the event buffer"),
    ]
    for method, path, desc in endpoints:
        table.add_row(method, path, desc)

    console.print(Panel("\n".join(banner_lines), title="[bold]Sentinel Agent[/bold]", border_style="cyan"))
    console.print(table)
    console.print()
    console.print(f"  [dim]API docs  : http://localhost:<PORT>/docs[/dim]")
    console.print(f"  [dim]Redoc     : http://localhost:<PORT>/redoc[/dim]")
    console.print()

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
_CLI_ARGS: Optional[argparse.Namespace] = None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Supply Chain Sentinel -- eBPF Monitoring Agent HTTP Server"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7777,
        help="Port to listen on (default: 7777)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--container",
        default=None,
        help="Container name/ID to auto-start monitoring on startup",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Auto-stop monitoring after DURATION seconds (only with --container)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Path for event log output",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _CLI_ARGS = _parse_args()

    if _CLI_ARGS.duration and _CLI_ARGS.container:
        # Schedule auto-stop via a background thread
        def _auto_stop():
            time.sleep(_CLI_ARGS.duration)
            logger.info("Duration %ds elapsed -- stopping monitoring", _CLI_ARGS.duration)
            _stop_monitoring()

        threading.Thread(target=_auto_stop, daemon=True, name="auto-stop").start()

    uvicorn.run(
        app,
        host=_CLI_ARGS.host,
        port=_CLI_ARGS.port,
        log_level="info",
    )
